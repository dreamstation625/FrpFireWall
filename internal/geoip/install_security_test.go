package geoip

import (
	"io"
	"testing"
	"time"
)

type heldReader struct {
	entered chan struct{}
	release chan struct{}
}

func (r *heldReader) Read([]byte) (int, error) {
	close(r.entered)
	<-r.release
	return 0, io.EOF
}

func TestUploadsSerializeBeforeReadingAndLeaveNoTemporaryFiles(t *testing.T) {
	dir := t.TempDir()
	r := New(dir)
	first := &heldReader{make(chan struct{}), make(chan struct{})}
	second := &heldReader{make(chan struct{}), make(chan struct{})}
	done := make(chan error, 2)
	go func() { done <- r.SaveUpload(FileCountry, first) }()
	<-first.entered
	go func() { done <- r.SaveUpload(FileCountry, second) }()
	select {
	case <-second.entered:
		close(first.release)
		close(second.release)
		<-done
		<-done
		t.Fatal("第二次安装在第一次安装完成前读取了输入")
	case <-time.After(50 * time.Millisecond):
	}
	close(first.release)
	select {
	case <-second.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("第二次安装未恢复")
	}
	close(second.release)
	for range 2 {
		if err := <-done; err == nil {
			t.Fatal("空数据库应该校验失败")
		}
	}
	assertNoLeftovers(t, dir)
}
