package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	_ "net/http/pprof"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/lucas-clemente/quic-go/internal/testdata"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/logging"
	"github.com/lucas-clemente/quic-go/qlog"
)

type binds []string

func (b binds) String() string {
	return strings.Join(b, ",")
}

func (b *binds) Set(v string) error {
	*b = strings.Split(v, ",")
	return nil
}

// Size is needed by the /demo/upload handler to determine the size of the uploaded file
type Size interface {
	Size() int64
}

// See https://en.wikipedia.org/wiki/Lehmer_random_number_generator
func generatePRData(l int) []byte {
	res := make([]byte, l)
	seed := uint64(1)
	for i := 0; i < l; i++ {
		seed = seed * 48271 % 2147483647
		res[i] = byte(seed)
	}
	return res
}

// ---------------------------------------------

type AppSet struct {
	app_name           string
	feature_lst        []string
	all_cnt_lst        [][]string
	whether_stat_lst   []bool
	num_periodical_fwd int
}

type CookieHandler struct {
	analytics_ip      string
	analytics_port    int
	app_set           []AppSet
	send_cookie_to_as bool
}

func (c *CookieHandler) generate_as_message(app string, app_set []AppSet, cookies []*http.Cookie) []byte {
	message := []byte{
		00, 41, // identifier
		00, 00, 00, md5.Sum([]byte(app))[0], // app_id
		01, 02, 03, 04, 05,
		01, 02, 03, 04, 05,
		01, 02, 03, 04, 05,
		01, 02, 03, 04, 05,
	}
	time.Sleep(1 * time.Millisecond)
	// log.Println(time.Now().UnixNano(), "generate_as_message", message)
	return message
}

// ---------------------------------------------

func setupHandler(cookie_handler *CookieHandler, pool *x509.CertPool, url string) http.Handler {
	mux := http.NewServeMux()

	as_url := fmt.Sprintf("%v:%v", cookie_handler.analytics_ip, cookie_handler.analytics_port)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%d, Request %#v\n", time.Now().UnixNano(), r)
		// log.Println(time.Now().UnixNano(), "accessed", r.RequestURI)
		// log.Println(time.Now().UnixNano(), "cookies", r.Cookies())

		as_conn, err := net.Dial("udp", as_url)
		if err != nil {
			log.Printf("%d, Dial err %v", time.Now().UnixNano(), err)
			os.Exit(-1)
		}
		defer as_conn.Close()
		log.Println(time.Now().UnixNano(), "as", as_url, as_conn)

		message := cookie_handler.generate_as_message(r.RequestURI, cookie_handler.app_set, r.Cookies())
		if _, err = as_conn.Write(message); err != nil {
			log.Printf("%d, Write err %v", time.Now().UnixNano(), err)
			// os.Exit(-1)
		}

		var quicClientConf quic.Config
		// quicClientConf.Cookies = []byte{255, 255, 255, 255, 255}
		var keyLog io.Writer
		roundTripper := &http3.RoundTripper{
			TLSClientConfig: &tls.Config{
				RootCAs:            pool,
				InsecureSkipVerify: false,
				KeyLogWriter:       keyLog,
			},
			QuicConfig: &quicClientConf,
		}
		defer roundTripper.Close()
		hclient := &http.Client{
			Transport: roundTripper,
		}

		log.Printf("%d, GET %s", time.Now().UnixNano(), url)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			log.Fatal(err)
		}
		for _, cookie := range r.Cookies() {
			req.AddCookie(cookie)
		}
		log.Println(time.Now().UnixNano(), req)

		start := time.Now()
		rsp, err := hclient.Do(req)
		if err != nil {
			log.Fatal(err)
		}
		t := time.Now()
		elapsed := t.Sub(start)
		log.Println(time.Now().UnixNano(), "Time cost", elapsed)
		log.Printf("%d, Got response for %s: %#v", time.Now().UnixNano(), url, rsp)

		body := &bytes.Buffer{}
		_, err = io.Copy(body, rsp.Body)
		if err != nil {
			log.Fatal(err)
		}
		// if *quiet {
		log.Printf("%d, Response Body: %d bytes", time.Now().UnixNano(), body.Len())
		// } else {
		// 	logger.Infof("Response Body:")
		// 	logger.Infof("%s", body.Bytes())
		// }
		// wg.Done()
		ret := body.Bytes()

		w.Write(ret)
	})

	return mux
}

func main() {
	// defer profile.Start().Stop()
	go func() {
		log.Println(time.Now().UnixNano(), http.ListenAndServe("localhost:45679", nil))
	}()
	// runtime.SetBlockProfileRate(1)

	verbose := flag.Bool("v", false, "verbose")
	bs := binds{}
	flag.Var(&bs, "bind", "bind to")
	// www := flag.String("www", "html", "www data")
	tcp := flag.Bool("tcp", false, "also listen on TCP")
	enableQlog := flag.Bool("qlog", false, "output a qlog (in the same directory)")
	app_conf := flag.String("app_conf", "../app_info.json", "filename for app set configuration")
	flag.Parse()
	url := "https://10.10.70.2:45680/app1"

	logger := utils.DefaultLogger

	if *verbose {
		logger.SetLogLevel(utils.LogLevelDebug)
	} else {
		logger.SetLogLevel(utils.LogLevelInfo)
	}
	logger.SetLogTimeFormat("")

	if len(bs) == 0 {
		bs = binds{"localhost:45679"}
	}

	// fmat.Println(*www)
	// handler := setupHandler(*www)

	jsonFile, err := os.Open(*app_conf)
	if err != nil {
		log.Fatal(err)
	}
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	if err != nil {
		log.Fatal(err)
	}

	app_set := []AppSet{}
	if err := json.Unmarshal(byteValue, &app_set); err != nil {
		log.Fatal(err)
	}
	log.Println(time.Now().UnixNano(), app_set)

	pool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal(err)
	}
	testdata.AddRootCA(pool)

	cookie_handler := &CookieHandler{
		analytics_ip:      "10.10.80.3",
		analytics_port:    45681,
		app_set:           app_set,
		send_cookie_to_as: true,
	}
	handler := setupHandler(cookie_handler, pool, url)
	quicServerConf := &quic.Config{}
	if *enableQlog {
		quicServerConf.Tracer = qlog.NewTracer(func(_ logging.Perspective, connID []byte) io.WriteCloser {
			filename := fmt.Sprintf("server_%x.qlog", connID)
			f, err := os.Create(filename)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("%d, Creating qlog file %s.\n", time.Now().UnixNano(), filename)
			return utils.NewBufferedWriteCloser(bufio.NewWriter(f), f)
		})
	}

	var wg sync.WaitGroup
	wg.Add(len(bs))
	for _, b := range bs {
		bCap := b
		go func() {
			var err error
			if *tcp {
				certFile, keyFile := testdata.GetCertificatePaths()
				err = http3.ListenAndServe(bCap, certFile, keyFile, handler)
			} else {
				server := http3.Server{
					Server:     &http.Server{Handler: handler, Addr: bCap},
					QuicConfig: quicServerConf,
				}
				err = server.ListenAndServeTLS(testdata.GetCertificatePaths())
			}
			if err != nil {
				log.Println(time.Now().UnixNano(), err)
			}
			wg.Done()
		}()
	}
	wg.Wait()
}
