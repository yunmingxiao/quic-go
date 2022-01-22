package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/lucas-clemente/quic-go/internal/testdata"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

func main() {
	verbose := flag.Bool("v", false, "verbose")
	quiet := flag.Bool("q", false, "don't print the data")
	keyLogFile := flag.String("keylog", "", "key log file")
	insecure := flag.Bool("insecure", false, "skip certificate verification")
	// enableQlog := flag.Bool("qlog", false, "output a qlog (in the same directory)")
	numRequest := flag.Int("numq", 1, "number of requests")
	freq := flag.Int("frequency", 1000, "frequency of requests")
	flag.Parse()
	// urls := flag.Args()
	url := "https://10.200.20.101:45679/app1"

	logger := utils.DefaultLogger

	if *verbose {
		logger.SetLogLevel(utils.LogLevelDebug)
	} else {
		logger.SetLogLevel(utils.LogLevelInfo)
	}
	logger.SetLogTimeFormat("")

	var keyLog io.Writer
	if len(*keyLogFile) > 0 {
		f, err := os.Create(*keyLogFile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		keyLog = f
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal(err)
	}
	testdata.AddRootCA(pool)

	var wg sync.WaitGroup
	wg.Add(*numRequest)
	for i := 0; i < *numRequest; i++ {
		logger.Infof("Request %d", i)
		go func(url string) {
			var qconf quic.Config
			qconf.Cookies = []byte{03, 248, 63, 219} // "3c03f83fdb18d87b" //[]byte{255, 255, 255, 255, 255}
			roundTripper := &http3.RoundTripper{
				TLSClientConfig: &tls.Config{
					RootCAs:            pool,
					InsecureSkipVerify: *insecure,
					KeyLogWriter:       keyLog,
				},
				QuicConfig: &qconf,
			}
			defer roundTripper.Close()
			hclient := &http.Client{
				Transport: roundTripper,
			}
			// logger.Infof("client cookies", qconf.Cookies)

			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				log.Fatal(err)
			}
			req.AddCookie(&http.Cookie{Name: "test", Value: "111"})
			log.Println(req)

			log.Println("client start time", time.Now().UnixNano())
			start := time.Now()
			rsp, err := hclient.Do(req)
			if err != nil {
				log.Fatal(err)
			}
			t := time.Now()
			elapsed := t.Sub(start)
			log.Println("Time cost", elapsed)
			logger.Infof("Got response for %s: %#v", url, rsp)

			body := &bytes.Buffer{}
			_, err = io.Copy(body, rsp.Body)
			if err != nil {
				log.Fatal(err)
			}
			if *quiet {
				logger.Infof("Response Body: %d bytes", body.Len())
			} else {
				logger.Infof("Response Body:")
				logger.Infof("%s", body.Bytes())
			}
			wg.Done()
		}(url)

		time.Sleep(time.Duration(*freq) * time.Millisecond)
	}
	wg.Wait()
}
