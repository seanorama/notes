AWS Tuning for RedHat/CentOS EL7
==========

What these changes provided:
- Change clocksource to tsc https://aws.amazon.com/premiumsupport/knowledge-center/manage-ec2-linux-clock-source/
- Change cstate to 1 https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/processor_state_control.html
- ST1: setra and grub settings: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSPerformance.html

Add to /etc/default/grub:
```
GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX transparent_hugepage=never"
GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX clocksource=tsc tsc=reliable"
GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX intel_idle.max_cstate=1"
GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX xen_blkfront.max=256"
```

Execute:
```
sudo grub2-mkconfig -o /boot/grub2/grub.cfg
```


