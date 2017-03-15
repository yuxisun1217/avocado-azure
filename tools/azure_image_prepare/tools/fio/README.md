Requirement:
    1.Prepare VM
        D1V2 with 2 data disks
        D14V2 with 32 data disks
        DS1 with 2 disks(one P10 level disk,one P30 level disk)   
        DS14 with 2 disks(one P10 level disk,one P30 level disk)
        Note:Must first add P10 disk and then add P30 disk(add order will affect disk name)
        注意：先添加的data disk 会使用sdc这个名字，后添加的会使用sdd（即添加顺序会影响设备的名字），脚本中先测试的是P10 disk，所以需要注意以下顺序
   2.Execute script
        bash run-ds14.sh
