# img4tool
_A tool for manipulating IMG4, IM4M and IM4P files_

# BUILD
Install dependencies:
* Buildsystem
  * autoconf
  * automake
  * libtool
  * pkg-config
* External
  * openssl
  * libplist-2.0
* tihmstar's tools
  * [libgeneral](https://github.com/tihmstar/libgeneral)

To compile run:

```bash
./autogen.sh
make
sudo make install
```


# Features
## Print
* Print IMG4, IM4P, IM4M
  * `img4tool infile.img4`
  * `-a` print everything from im4m
  * `-i` print only im4p

## Extract
* ### Extract from IMG4
  * Extract IM4P
    * `img4tool -e -p out.im4p in.img4`
  * Extract IM4M
    * `img4tool -e -m out.im4m in.img4`  

* ### Extract from SHSH
  * Extract IM4P
    * `img4tool -e -p out.im4p -s in.shsh`

* ### Extract from IM4P
  * Extract Payload
    * `img4tool -e -o out.bin in.im4p`
  * Extract and decrypt payload
    * `img4tool -e --iv <IV> --key <KEY> -o out.bin in.im4p`

## Create
* ### Create IMG4
  * Create IMG4 with IM4P
    * `img4tool -c out.img4 -p in.im4p`
  * Create IMG4 with IM4P and IM4M
    * `img4tool -c out.img4 -p in.im4p -m in.im4m`
  * Create IMG4 with IM4P and SHSH
    * `img4tool -c out.img4 -p in.im4p -s in.shsh`
* ### Create IM4P
  * Create IM4P with type _ibss_
    * `img4tool -c out.im4p -t ibss IBSS.raw`
  * Create IM4P with type _ibss_ and custom desc
    * `img4tool -c out.im4p -t ibss -d "Pwned iBSS no sigpatches" IBSS.raw`

## Rename (change IM4P type)
* `img4tool -n rkrn -p kernel.im4p`

## Convert SHSH to IM4M
* `img4tool --convert -s out.shsh in.im4m`

## Verify
* ### Verify APTicket is valid for BuildManifest
  * Verify IM4M
    * `img4tool --verify BuildManifest.plist ticket.im4m`
  * Verify SHSH
    * `img4tool --verify BuildManifest.plist -s ticket.shsh`
* ### Verify IMG4 is correctly signed for BuildManifest
  * `img4tool --verify BuildManifest.plist in.img4` //needs to contain IM4P and IM4M
