all: basic_tutorial_switch

basic_tutorial_switch: basic_tutorial_switch.p4
	p4c-bm2-ss --std p4-16 \
		--target bmv2 --arch v1model \
		-o basic_tutorial_switch.json \
		--p4runtime-file basic_tutorial_switch.p4info \
		--p4runtime-format text basic_tutorial_switch.p4

controller:
	sudo python p4_controller.py \
    	--p4info basic_tutorial_switch.p4info \
    	--bmv2-json basic_tutorial_switch.json 

clean: 
	sudo rm -rf logs/ pcaps/ basic_tutorial_switch.json basic_tutorial_switch.p4info