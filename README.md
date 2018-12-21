# MIMIR
Researching work on anomaly detection with SDN / PDP.

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
│   └── utils
├── algorithm
├── resource
├── dataset
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
| `paper` | Paper work of MIMIR. Using LaTeX as our tool to write the paper. |  x | kevinbird61 | |