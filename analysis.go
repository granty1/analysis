package main

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/mediocregopher/radix.v2/pool"
	"github.com/mgutz/str"
	"github.com/sirupsen/logrus"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	PREFIX      = "dig?"
	END         = "HTTP"
	RoutePrefix = "http://"
)

type cmdParams struct {
	filePath   string
	routineNum int
}

type digData struct {
	url   string
	time  string
	refer string
	ua    string
}

type urlData struct {
	data   digData
	uid    string
	unNode urlNode
}

type urlNode struct {
	unType string
	unRid  string
	unUrl  string
	unTime string
}

type storageBlock struct {
	counterType  string
	storageModel string
	uNode        urlNode
}

var log = logrus.New()

func init() {
	log.Out = os.Stdout
	log.Level = logrus.DebugLevel
}

func main() {
	// get log data
	filePath := flag.String("p", "/usr/local/Cellar/nginx/1.17.3_1/logs/dig.log", "log file path.")
	routineNum := flag.Int("n", 5, "num of goroutine.")
	target := flag.String("t", "/Users/Grant/logs/analysis/log", "target file.")

	params := cmdParams{
		*filePath,
		*routineNum,
	}

	logFile, err := os.OpenFile(*target, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
	if err == nil {
		log.Out = logFile
		defer logFile.Close()
	}

	log.Infoln("Analysis Process Start.")
	log.Infof("Params: filePath=%s, routineNumber=%d, targetLogFilePath=%s", *filePath, *routineNum, *target)

	// define channel
	logChannel := make(chan string, *routineNum)
	pvChannel := make(chan urlData, *routineNum)
	uvChannel := make(chan urlData, *routineNum)
	storageChannel := make(chan storageBlock, *routineNum)

	redisPool, err := pool.New("tcp", "127.0.0.1:6379", 2 * params.routineNum)
	if err != nil {
		log.Warningln("Main Redis pool open fail.")
	} else {
		log.Infoln("Main redis connect.")
		go func(redisPool *pool.Pool) {
			for {
				redisPool.Cmd("PING")
				time.Sleep(3 * time.Second)
				log.Infoln("Redis: Ping redis.")
			}
		}(redisPool)
	}
	// read data
	go readFileByLine(params, logChannel)

	// log consumer
	for i := 0; i < params.routineNum; i++ {
		go logCustomer(logChannel, pvChannel, uvChannel)
	}

	// create pv uv counter
	go pvCounter(pvChannel, storageChannel)
	go uvCounter(uvChannel, storageChannel, redisPool)

	// storage data
	go storageData(storageChannel)

	// prevent main goroutine exit
	time.Sleep(1000 * time.Second)
}

func readFileByLine(params cmdParams, logChannel chan string) error {
	log.Info("readFileByLine method start.")
	file, err := os.Open(params.filePath)
	if err != nil {
		log.Errorf("readFileByLine method open file:%s fail.", params.filePath)
	}
	count := 0
	reader := bufio.NewReader(file)
	for {
		line, _, err := reader.ReadLine()
		logChannel <- string(line)
		count++
		if count%(1000*params.routineNum) == 0 {
			log.Infof("readFileByLine Line : %d", count)
		}
		if err != nil {
			if err == io.EOF {
				// read the end of log
				time.Sleep(3 * time.Second)
				log.Infof("readFileByLine Sleep three seconds.")
			} else {
				log.Warningf("readFileByLine read line error:%s at line:%d", err, count)
			}
		}
	}
}

func logCustomer(logChannel chan string, pvChannel chan urlData, uvChannel chan urlData) {
	for line := range logChannel {
		data := cutDigDataFromLine(line)
		harsher := md5.New()
		harsher.Write([]byte(data.refer + data.ua))
		uid := hex.EncodeToString(harsher.Sum(nil))

		uData := urlData{data, uid, formatData(data.refer, data.time, uid)}
		pvChannel <- uData
		uvChannel <- uData
	}
}

func cutDigDataFromLine(line string) digData {
	// remove space
	line = strings.TrimSpace(line)
	pre := str.IndexOf(line, PREFIX, 0)
	if pre == -1 {
		return digData{}
	}
	pre += len(PREFIX)

	end := str.IndexOf(line, END, pre)
	target := str.Substr(line, pre, end-pre)
	parse, err := url.Parse("http://localhost/?" + target)
	if err != nil {
		return digData{}
	}
	values := parse.Query()
	return digData{
		values.Get("url"),
		values.Get("time"),
		values.Get("refer"),
		values.Get("ua"),
	}
}

func pvCounter(pvChannel chan urlData, storageChannel chan storageBlock) {
	for pv := range pvChannel {
		storageChannel <- storageBlock{
			counterType:  "pv",
			storageModel: "ZINCREBY",
			uNode:        pv.unNode,
		}
	}
}

func uvCounter(uvChannel chan urlData, storageChannel chan storageBlock, redisPool *pool.Pool) {
	for uv := range uvChannel {
		// HyperLogLog redis
		hyperLogLogKey := "uv_hpll_" + uv.data.refer
		res, err := redisPool.Cmd("PFADD", hyperLogLogKey, uv.uid, "EX", 86400).Int()
		if err != nil {
			log.Warningln("uvCounter PFADD redis fail.")
		}
		if res != 1 {
			continue
		}
		storageChannel <- storageBlock{
			counterType:  "uv",
			storageModel: "ZINCREBY",
			uNode:        uv.unNode,
		}
	}
}

func storageData(storageChannel chan storageBlock) {
	for sto := range storageChannel {
		fmt.Printf("%v\n", sto.uNode)
	}
}

func formatData(url, time, uid string) urlNode {
	pre := str.IndexOf(url, RoutePrefix, 0)
	if pre != -1 {
		preRoute := str.Substr(url, len(RoutePrefix), len(url) - len(RoutePrefix))
		pre = str.IndexOf(preRoute, "/", 0)
		if pre != -1 {
			route := str.Substr(preRoute, pre+len("/"), len(preRoute)-1)
			return urlNode{
				unType: route,
				unRid:  uid,
				unUrl:  url,
				unTime: time,
			}
		}
	}
	return urlNode{}
}

func getTimeFormat(date string, format string) string {
	switch format {
	case "day":
		format = "2016-01-02"
		break
	case "hour":
		format = "2016-01-02 15"
		break
	case "minute":
		format = "2016-01-02 15:04"
		break
	case "second":
		format = "2016-01-02 15:04:05"
		break
	}
	data, _ := time.Parse(format, date)
	return strconv.FormatInt(data.Unix(), 10)
}
