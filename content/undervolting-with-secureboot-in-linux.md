+++
title = "Undervolting with SecureBoot in Linux"
date = 2020-06-24
[taxonomies]
tags = ["linux", "secureboot", "undervolt", "undervolting"]
+++

Many laptop users choose to undervolt their machines. This decreases thermal output, which, in turn, can increase program performance, since modern CPUs will automatically adjust their operating frequency depending on the available thermal headroom. Undervolting tools exist for all major operating systems; they typically require administrator rights, but otherwise are easy to use. In Linux, however, things aren't quite so simple: recent versions of the kernel prohibit the mechanism used for undervolting Intel CPUs when SecureBoot is enabled. The most common way around this, unsurprisingly, is just to disable SecureBoot. With a bit of work, though, it is possible to keep SecureBoot enabled, but allow controlled access to the undervolting mechanism.

<!-- more -->

The next sections will go into some background information on undervolting, SecureBoot, and why newer versions of Linux prevent the former while the latter is enabled. You can skip any of these if you're already familiar with the topic.

# Background: Undervolting

Some laptops today are well-known for having thermal issues. A common culprit is that these laptops ship with voltage settings that are higher than actually required. This is a good default behavior, since chips' performance can vary significantly, even within a SKU. High-end chips that are put into more expensive models of these laptops, however, tend to be better binned, and often work without errors at substantially lower voltage. Since all modern chips implement some sort of "auto-overclock" when there is enough thermal headroom, this can translate into increased clock speeds, and thus, better performance.

My current laptop is a Dell XPS 15 7590, with an 8-core Intel&reg; i9-9980HK. This particular model performs better compared to its predecessors, but there is still room for improvement. Unfortunately, Dell's UEFI provides no way to control the voltage settings, so any adjustments must be done after booting up.

# Background: SecureBoot & Machine-owner Keys (MOK)

The [Debian Wiki](https://wiki.debian.org/SecureBoot#What_is_UEFI_Secure_Boot.3F) has a great explanation of SecureBoot and Machine Owner Keys:

> UEFI Secure Boot (SB) is a verification mechanism for ensuring that code launched by a computer's UEFI firmware is trusted. It is designed to protect a system against malicious code being loaded and executed early in the boot process, before the operating system has been loaded. SB works using cryptographic checksums and signatures. Each program that is loaded by the firmware includes a signature and a checksum, and before allowing execution the firmware will verify that the program is trusted by validating the checksum and the signature. When SB is enabled on a system, any attempt to execute an untrusted program will not be allowed. This stops unexpected / unauthorized code from running in the UEFI environment.
>
> ...
>
> A key part of the shim design is to allow users to control their own systems. The distro CA key is built in to the shim binary itself, but there is also an extra database of keys that can be managed by the user, the so-called Machine Owner Key (MOK for short).

Large distros, like Ubuntu, ship with kernels signed by the same CA key used by Microsoft for Windows. This lets them be installed onto systems with SecureBoot without making the user go through the hassle of registering their own MOK and signing the kernel manually. If you want to run any custom kernel modules, however, you must create and register a MOK with the UEFI, and sign the driver(s) with it, or the kernel will refuse the load them.

# Background: Linux and its `msr` module

Intel CPUs have had MSRs&mdash;*model-specific registers*&mdash;for quite some time. All sorts of tracing and debugging functionality is available through them, but, importantly for this topic, this is also how they provide a way to dynamically adjust voltages applied to the core and caches of the CPU. More troubling, though, is that these registers can also be used to violate protection rings, allowing user applications to read *and write* over kernel memory, including kernel code. This is why applications that use the MSRs have always required some sort of elevated privileges.

Previously, programs that wrote to the MSRs only required the `SYS_RAWIO` capability in Linux. Recent version of the kernel, however, don't allow any writes to the MSRs whatsoever when SecureBoot is enabled. (In kernel parlance, this is called "lockdown mode.") The motivation here is sound: the entire purpose of SecureBoot is to have a trusted environment that runs only the exact code that's been authorized, so any mechanism that potentially allows modification of kernel code at runtime flies in the face of that goal.

There has been at least [one recent proposal](https://lore.kernel.org/linux-security-module/38d18a24-c580-d56b-f0cd-91e8184e1f0d@gmail.com/T/) to open up the subset of MSRs used for undervolting, even when the kernel is locked down. A consensus hasn't yet been reached, though, so for the time being, we must come up with our own solutions.

# Solution: Custom `msr` module

tl;dr: the easiest way to allow undervolting in Linux while using SecureBoot:

* Generate your own MOK and register it with the UEFI.
* Patch the `msr` module to remove the checks for lockdown mode.
* Build, sign, and install the patched module.
* Install an undervolting tool, like `intel-undervolt`, and give it the
  `RAW_IO` capability.
* Rejoice!

In my case, Ubuntu 20.04 uses kernel v5.4.0, and the patch looks like this:

```patch
--- ./linux-source-5.4.0/arch/x86/kernel/msr.c.orig
+++ ./linux-source-5.4.0/arch/x86/kernel/msr.c
@@ -77,15 +77,15 @@
        u32 data[2];
        u32 reg = *ppos;
        int cpu = iminor(file_inode(file));
        int err = 0;
        ssize_t bytes = 0;

-       err = security_locked_down(LOCKDOWN_MSR);
-       if (err)
-               return err;
+       //err = security_locked_down(LOCKDOWN_MSR);
+       //if (err)
+       //      return err;

        if (count % 8)
                return -EINVAL; /* Invalid chunk size */

        for (; count; count -= 8) {
                if (copy_from_user(&data, tmp, 8)) {
@@ -132,15 +132,15 @@
                        break;
                }
                if (copy_from_user(&regs, uregs, sizeof(regs))) {
                        err = -EFAULT;
                        break;
                }
-               err = security_locked_down(LOCKDOWN_MSR);
-               if (err)
-                       break;
+               //err = security_locked_down(LOCKDOWN_MSR);
+               //if (err)
+               //      break;
                err = wrmsr_safe_regs_on_cpu(cpu, regs);
                if (err)
                        break;
                if (copy_to_user(uregs, &regs, sizeof(regs)))
                        err = -EFAULT;
                break;
```

Pretty straightforward: look for all instances of `LOCKDOWN_MSR` in this file,
and comment-out the lockdown check & error-handling code.

# Impact

For all tests, these are the undervolt settings:

| Component | &Delta;mV |
| --------- | --------- |
| CPU Core  | -99.6mV   |
| CPU Cache | -99.6mV   |

The first test is running Prime95 with default settings. Starting with the undervolt applied, I let the CPU frequency and temperature settle. Then, I set the voltage to stock settings, and let the system settle again. Measurements were done using the `intel-undervolt` tool. Here's the averaged & rounded results:

| Voltages    | CPU Core (W) | CPU Core (&deg;C) | CPU Core (Hz) |
| ----------- | ------------ | ----------------- | ------------- |
| Stock       | 38 W         | 92 &deg;C         | 2350 Hz       |
| Undervolted | 34 W         | 92 &deg;C         | 2950 Hz       |

To see how this change would affect a realistic workload for myself, I compiled the latest trunk branches of Firefox and alacritty. Both of these runs were done with the same settings, and with a clean build tree.

| Voltages    | Firefox Time (s) | alacritty time (s) |
| ----------- | ---------------- | ------------------ |
| Stock       | 1401 s           | 139 s              |
| Undervolted | 1273 s           | 129 s              |

These are only brief, non-rigorous tests, but the results suggest that undervolting can provide tangible benefits.

# Alternatives

The obvious objection to this solution, of course, is that it makes SecureBoot useless. Or does it? If your system has multiple tenants, some of whom require the ability to grant programs the `SYS_RAWIO` capability, then this objection holds water. For the vast majority of laptop users, though, this isn't a threat. The owner decides which programs are allowed to perform raw I/O, and is responsible for their own security.

As for the common solution to this problem&mdash;disabling SecureBoot entirely&mdash;the drawbacks are pretty clear: you're throwing the baby out with the bathwater, abandoning any sense of security and peace-of-mind that comes from cryptographic verification of your operating system. Users shouldn't have to sacrifice critical security features for acceptable performance.

The best solution would satisfy the needs of both server and desktop use cases. If the kernel had an interface to control undervolting, without providing access to the raw MSRs, then we could have the best of both worlds: no way to violate the SecureBoot contract from userspace, and laptop users can get better performance. Designing a good, reusable interface for this would undoubtedly take some time; we don't want it to be married specifically to one vendor, architecture, or platform. Until such an interface gets made and merged, we'll have to stick to workarounds.

# Conclusion

Undervolting can provide noticeable benefits for many laptop configurations. Unfortunately, some OEMs prevent adjusting these settings in their UEFI, requiring the use of runtime mechanisms. Even *more* unfortunately, the mechanism for Intel CPUs also comes with potential security holes, which make it a challenge to provide this functionality in a way that completely complies with protocols like SecureBoot. Linux, in particular, takes the most conservative approach, absolutely forbidding access to undervolting mechanisms when running under a secure context. That is a sane starting point, but it would certainly be worthwhile to figure out an acceptable solution.
