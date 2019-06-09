package main

// Build the virtual environment for testing framework.
// * create benign hosts 
// * create attacker, victim (default: 1)
// * run benign (iperf)
// * run attacker 

import (
    "fmt"
    //"net/url"
    "time"
    "os/exec"
    "os"
    "flag"
    "strconv"
)

// running command in bash environment (linux-based)
func exec_command(program string, args ...string) {
    cmd := exec.Command(program, args...)
    cmd.Stdin = os.Stdin;
    cmd.Stdout = os.Stdout;
    cmd.Stderr = os.Stderr;
    err := cmd.Run()

    if err != nil {
        fmt.Printf("%v\n", err)
    }
}

func create_benign_host(num int) {
    // default is creating symetric network
    // atk
    for i:=0; i< num; i++ {
        exec_command("./build.sh", "create", "user_a"+strconv.Itoa(i), "atk")
    }
    // vic
    for i:=0; i< num; i++ {
        exec_command("./build.sh", "create", "user_v"+strconv.Itoa(i), "vic")
    }
}

func run_benign_host(num int, duration int) {
    // all benign host are running iperf client 
    // FIXME: do all hosts send iperf traffic to victim? or atk_benign_host->vic, vic_benign_host->atk ?
    // atk
    for i:=0; i< num; i++ {
        exec_command("docker", "exec", "-i", "-d" , "user_a"+strconv.Itoa(i), "iperf", "-t", strconv.Itoa(duration), "-c", "victim")
    }
    // vic
    for i:=0; i< num; i++ {
        exec_command("docker", "exec", "-i", "-d" , "user_v"+strconv.Itoa(i), "iperf", "-t", strconv.Itoa(duration), "-c", "victim")
    }
}

func main(){
	// Args 
    benign_hosts :=     flag.Int("b", 10, "Number of benign hosts under each network domain. (Victim/Attacker)")
    verbose :=          flag.Bool("v", false, "Verbose mode.")
    victim_ip :=        flag.String("vip", "127.0.0.1", "Victim's IP address.")
    victim_port :=      flag.Int("vport", 80, "Victim's Port number.")
    round :=            flag.Int("round", 10, "How many iperf tests will be executed." )
    duration :=         flag.Int("dur", 20, "How long will iperf be executed.")
    delay :=            flag.Int("del", 20, "Delay (seconds) between virtual network creation and running attack.")
    clean :=            flag.Bool("c", false, "Clean all container.")

    flag.Parse()
    
    // Print out all profile specify
    fmt.Println("============================================================")
    fmt.Println("Number of benign hosts: ", *benign_hosts)
    fmt.Println("Verbose mode: ", *verbose)
    // check IP address is valid or not
    fmt.Println("Victim IP address: ", *victim_ip)
    if *victim_port < 0 || *victim_port > 65535 {
        fmt.Println("Invalid port. Value need to set between 1~65535.")
        os.Exit(1)
    }
    fmt.Println("Victim Port number: ", *victim_port)
    fmt.Println("Delay duration: ", *delay)
    fmt.Println("Service running duration: ", *duration)
    fmt.Println("============================================================")

    if *clean {
        fmt.Println("Clean all executable container.")
        exec_command("./build.sh", "clean")
    } else {
        // init 
        exec_command("./build.sh", "init")
        // first create container from pre-build docker images
        create_benign_host(*benign_hosts)
        // create attacker 
        exec_command("./build.sh", "create", "attacker", "atk")
        exec_command("./build.sh", "create", "victim", "vic")
        // run service on those virtual devices
        // running iperf server on victim (FIXME: need to change ?)
        go exec_command("docker", "exec", "-i", "-d", "victim", "iperf", "-s")
        // recording 
        go exec_command("docker", "exec", "-i", "-d", "victim", "tcpdump", "-i", "eth0", "-G", strconv.Itoa((*duration)*(*round+1)), "-w", "/home/ddos-with-iperf-tcp.pcap")

        // run several rounds, each will delay for period time before next iperf task.
        fmt.Println("=====================================================")
        for i:=0; i< *round; i++ {
            fmt.Println("Starting a new round ..., current round: ", strconv.Itoa(i))
            fmt.Println("Waiting for ", *delay, " seconds to start another round ...")
            fmt.Println("")
            // time sleep (wait for user to get into victim and start tcpdump to record traffic)
            time.Sleep(time.Duration(*delay)*time.Second)
            // running benign host (iperf -t duration -c victim )
            go run_benign_host(*benign_hosts, *duration)
            // running attacker (from external)
            go exec_command("docker", "exec", "-i", "-d", "attacker", "go", "run", "/home/ddos.go", "-ip=172.30.1."+strconv.Itoa(*benign_hosts+1), "-d="+strconv.Itoa(*delay)+"s")
            // running attacker (from internal)
            go exec_command("docker", "exec", "-i", "-d", "user_v0", "go", "run", "/home/ddos.go", "-ip=172.30.1."+strconv.Itoa(*benign_hosts+1), "-d="+strconv.Itoa(*delay)+"s")
        }
    }

}