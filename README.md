# CXL MCTP TESTY

This is a test script to test the functionality of setting up the LD FAM.
This script assumes you have Jonathan's fork of QEMU functioning and moking's 
cxl-test-tool.

```
https://lore-kernel.gnuweeb.org/qemu-devel/20250408043051.430340-1-nifan.cxl@gmail.com/
Part of .var.config, see run_vars.example
QEMU_ROOT=~/cxl/jic/qemu
# for FM VM
FM_KERNEL_ROOT=~/cxl/linux-v6.6-rc6/
FM_QEMU_IMG=~/cxl/images/qemu-image-fm.img

# for Target VM
KERNEL_ROOT=~/cxl/linux-dcd/
QEMU_IMG=~/cxl/images/qemu-image.img

command:
1. cxl-tool.py --run -T FM_TARGET
2. cxl-tool.py --attach-VM -T FM_CLIENT
3. cxl-tool.py --install-libcxlmi-fm
4. cxl-tool.py --setup-mctp-fm
5. cxl-tool.py --login-fm (run the test program with libcxlmi)
```

Use this topology:

```
-object memory-backend-file,id=cxl-mem1,mem-path=/tmp/t3_cxl1.raw,size=256M \
 -object memory-backend-file,id=cxl-lsa1,mem-path=/tmp/t3_lsa1.raw,size=1M \
 -object memory-backend-file,id=cxl-mem2,mem-path=/tmp/t3_cxl2.raw,size=512M \
 -object memory-backend-file,id=cxl-lsa2,mem-path=/tmp/t3_lsa2.raw,size=1M \
 -device pxb-cxl,bus_nr=12,bus=pcie.0,id=cxl.1,hdm_for_passthrough=true \
 -device cxl-rp,port=0,bus=cxl.1,id=cxl_rp_port0,chassis=0,slot=2 \
 -device cxl-upstream,port=2,sn=1234,bus=cxl_rp_port0,id=us0,addr=0.0,multifunction=on, \
 -device cxl-switch-mailbox-cci,bus=cxl_rp_port0,addr=0.1,target=us0 \
 -device cxl-downstream,port=0,bus=us0,id=swport0,chassis=0,slot=4 \
 -device cxl-downstream,port=1,bus=us0,id=swport1,chassis=0,slot=5 \
 -device cxl-downstream,port=3,bus=us0,id=swport2,chassis=0,slot=6 \
 -device cxl-type3,bus=swport0,memdev=cxl-mem1,id=cxl-pmem1,lsa=cxl-lsa1,sn=3 \
 -device cxl-type3,bus=swport2,memdev=cxl-mem2,id=cxl-pmem2,lsa=cxl-lsa2,sn=4 \
 -machine cxl-fmw.0.targets.0=cxl.1,cxl-fmw.0.size=4G,cxl-fmw.0.interleave-granularity=1k \
 -device i2c_mctp_cxl,bus=aspeed.i2c.bus.0,address=4,target=us0 \
 -device i2c_mctp_cxl,bus=aspeed.i2c.bus.0,address=5,target=cxl-pmem1 \
 -device i2c_mctp_cxl,bus=aspeed.i2c.bus.0,address=6,target=cxl-pmem2 \
 -device virtio-rng-pci,bus=swport1
```