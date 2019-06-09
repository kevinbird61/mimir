# Environmnet 

> Building our testing virtual network.

![](https://i.imgur.com/6ufrnFS.png)

## Login directly

```bash
$ docker pull kevinbird61/vnet
$ docker run -it --privileged kevinbird61/vnet
```

## Build with one command 

* 啟動 N 個 hosts 
```bash
$ go run build.go -b N
```
* 查看其他支援
```
$ go run build.go -h 
```
* 清除現有建立所有 container (reset)
```
$ go run build.go -c
```