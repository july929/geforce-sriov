# FAQ

Short answers to common questions. Each answer links to the page with the details.

## What it does

### What does geforce-sriov do?

It makes a supported GeForce card usable with NVIDIA's vGPU software, so several VMs can share the card.
Each VM gets its own virtual function (VF).
See [How it works](../README.md#how-it-works) for the parts and how they fit together.

### When do I need this?

You need it when you want several VMs, or the host and the VMs, to share one GeForce card instead of passing the whole card to one VM.
See [Motivation](../README.md#motivation) for what it changes.

### How is this different from GPU passthrough or mdev?

With passthrough, the card belongs to one VM.
With geforce-sriov, the host keeps the card and each VM gets its own SR-IOV VF, not an mdev (mediated device).
See [Motivation](../README.md#motivation) for the comparison and [Related projects](../README.md#related-projects) for mdev projects.

### Does it slow the GPU down?

No.
Most of its changes act at boot or when a VM starts, and none adds code to the path that runs the GPU's work.
See [Performance](../README.md#performance) for the comparison of a VM with the host.

### Does it make permanent hardware changes?

No.
It changes software only and writes no vBIOS.
The VFs and vGPU types are gone after every reboot or power-off, and installed files stay until you uninstall.
See [Safety and reversibility](../README.md#safety-and-reversibility) for every change.

### Is it safe to use?

It changes software only, makes no permanent hardware change, and installed files stay until you uninstall.
It is a beta, and some failures need a cold power cycle instead of a reboot.
See [Safety and reversibility](../README.md#safety-and-reversibility) and [Recovery](recovery.md#the-one-rule) for the details.

## What you need

### Does it bypass NVIDIA's vGPU licence?

No.
You need your own NVIDIA vGPU software and licence, and geforce-sriov does not touch licensing.
See [What you need](../README.md#what-you-need) for the files and their versions.

### How do I get a vGPU licence?

The licence comes from NVIDIA, through your NVIDIA vGPU software entitlement and the NVIDIA License System.
geforce-sriov does not provide, change or bypass licensing, and the guests' licensing is your responsibility.
See [NVIDIA License System documentation](https://docs.nvidia.com/license-system/latest/) for NVIDIA's own licensing steps.

### Where can I download the driver packages?

Get the vGPU host driver from the NVIDIA vGPU software download on the NVIDIA Licensing Portal, with your own NVIDIA entitlement.
The Linux driver package for host CUDA and the host desktop is either the vGPU guest driver from the same download or NVIDIA's GeForce driver from [NVIDIA's public Unix driver archive](https://download.nvidia.com/XFree86/Linux-x86_64/580.159.03/NVIDIA-Linux-x86_64-580.159.03.run).
The host display and desktop also use NVIDIA's public kernel module source, the [open-gpu-kernel-modules](https://github.com/NVIDIA/open-gpu-kernel-modules) tag 580.159.03.
geforce-sriov does not include or download any NVIDIA software.
See [What you need](../README.md#what-you-need) for each file, its exact version and when you need it.

### Which cards work?

Ampere and Ada cards from the device table work, laptop GPUs included.
See [Supported cards](devices.md#generations) for the table.

### Does it work with Turing, Pascal or Maxwell GPUs?

No, it works with Ampere and Ada cards.
NVIDIA does not support SR-IOV on Turing.
See [Related projects](../README.md#related-projects) for projects that use mdev for Turing and older cards.

### Does it work with professional cards that NVIDIA does not enable SR-IOV on?

Yes, if the card is in the device table.
The table has workstation cards such as the RTX A4000, RTX A2000 12GB, RTX 4500 Ada, RTX 4000 Ada and RTX 2000 Ada, and it handles them like the GeForce cards of their generation.
Professional cards that are not in the table are not presented or activated.
See [Supported cards](devices.md#rows) for the table and [Excluded](devices.md#excluded) for the cards it leaves out.

### Do laptop GPUs work?

Yes.
Ampere and Ada laptop GPUs use the same host stack and guest drivers as desktop cards of the same generation.
See [Laptop support](laptops.md) for the listed IDs and the power setting a laptop needs.

### Does this work on AMD GPUs?

No, it only works with NVIDIA Ampere and Ada cards from the device table.
See [Supported cards](devices.md#generations) for the table.

### Can I use different driver versions?

It is recommended to use the listed versions.
Other versions may also work: `install` then tries a best-effort build, and it stops without changing anything when it cannot find what it patches.
Other versions are **not** guaranteed to work.
See the [supported software stack](installation.md#supported-software-stack) for the details.

### Can I use any vGPU type of my card?

You can pick any type the card offers, but the list comes from the professional card and is not filtered by your card's memory.
Every VF of a card gets the same type, and all running vGPUs must fit in the card's VRAM together with the host driver's share.
See [Choosing a vGPU type](configuration.md#choosing-a-vgpu-type) for how to set it.

### Which host can I use?

A Linux x86_64 host with KVM and libvirt or QEMU, such as Proxmox VE.
It needs the IOMMU on and kernel 6.8 or later with livepatch support.
See [What you need](../README.md#what-you-need) for the full list.

### Does this work on Windows or Hyper-V?

The host is a Linux KVM host.
Windows runs as a guest.
See [What you need](../README.md#what-you-need) for the host and [Guests](installation.md#guests) for the guests.

## Running VMs

### Which guests can I use?

Linux and Windows guests work.
Each generation has its own guest driver versions, and every guest needs the setting `RMSetVgpuGspPluginOffloadMode=0`.
See [Guests](installation.md#guests) for the drivers and the setting.

### Does a VM need a modified guest driver?

No.
geforce-sriov installs nothing in a guest, and only the host driver is patched.
See [Guests](installation.md#guests) for the guest drivers and the setting they need.

### How many VMs can share one card?

Up to 4 VFs per card, so up to 4 VMs at a time.
The default is 4, and the `vfs` key in the config sets the count.
See [Known limits](ampere.md#known-limits) for the VF limits.

## The host

### Can the host still use the display?

Yes.
The console of each selected GPU can stay on through NVIDIA's display modules, and the optional host desktop feature lets the GPU draw the host desktop.
See [Boot display GPU](installation.md#boot-display-gpu) and [Host desktop](installation.md#host-desktop) for how each works.

### Does Wayland work on the host display?

The host desktop feature supports X11 desktops.
See [Host desktop](installation.md#host-desktop) for what it needs.

### Can the host still use CUDA?

Yes.
Host CUDA is optional and off by default.
See [Host CUDA](installation.md#host-cuda) for how to turn it on.

## Maintenance

### How do I upgrade or uninstall?

Uninstall the installed version, power the machine fully off and on, then install the new one.
A reboot is not enough.
Uninstall removes the config unless you edited it, so note your settings from `status` first.
See [Upgrading](installation.md#upgrading) and [Uninstall](installation.md#uninstall) for the steps.

### Why does it ask for a power cycle instead of a reboot?

A cold power cycle gives the card a clean start.
Several failures leave a card in a state that only a power loss clears.
See [The one rule](recovery.md#the-one-rule) for when it is needed and why you must not rescan the PCI bus.

### What do I do when something fails?

Run `geforce-sriov status` first, because it names each card's next step.
Run `geforce-sriov check` when a VM does not start.
See [Recovery](recovery.md#where-to-start) for the symptoms and fixes.

## Reporting

### How do I report that my card works or does not?

Open a compatibility report on GitHub, whether it works or not.
Remove private data from the output first.
See [Compatibility reports](compatibility.md) for what to collect and how to post it.
