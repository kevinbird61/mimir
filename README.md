# Mímir

Researching work on *anomaly detection* with SDN (software-defined network) / PDP (programmable data plane), which is named `Mímir`.

**Mímir** (Old Norse "The rememberer, the wise one") or Mim is a figure in Norse mythology, renowned for his **knowledge and wisdom**, who is beheaded during the Æsir-Vanir War. Afterward, the god Odin carries around Mímir's head and it recites secret knowledge and counsel to him.

## Project Layout

Planning of our project layout of MIMIR. 

```
.
├── eva
├── of
├── p4
│   ├── tool-diff
│   |   ├── polling-based
│   |   ├── pushing-based
│   ├── algo-diff
│   |   ├── TRW-CB
│   |   ├── entropy
│   |   ├── OpenWatch
│   ├── sys-diff
│   |   ├── single-switch
│   |   ├── multi-switches
│   ├── gran-diff
│   |   ├── sampling
│   |   ├── flowlet
│   └── utils
├── algorithm
├── resource
├── dataset
├── malware
└── paper
```

## Explanation of project layout

| Folder Path/Name | Purpose | Note | Maintainer | Progress |
| --- | --- | --- | --- | --- |
| `eva` | Evaluation of our scenario/pcap files. Aim to make the ground truth of our experiments. | x | kevinbird61 | 10% |
| `of` | Scenarios of OpenFlow version. | x | | |
| `p4` | Scenarios of P4 version. | x | kevinbird61 | |
| `algorithm` | Pseudo code / Implementation of detection algorithm. | x | kevinbird61 | |
| `resource` | Images, flowchart, explanation of program, useful documents, tutorials will place in here. | x | | |
| `dataset` | Download links of our source pcap files, and the evaluation of each pcap file (e.g. represent as its **ground truth**). Also these pcap files represent as benign traffic in our experiments. | Using *tcpdump/cisco flow recorder* to record the real traffic from real world. | kevinbird61 | 5% |
| `malware` | Attack pattern generator. | x | kevinbird61 | | 
| `paper` | Paper work of MIMIR. Using LaTeX as our tool to write the paper. |  x | kevinbird61 | |