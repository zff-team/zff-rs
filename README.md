# zff

Zff (Z forensic file format) is a completly new designed file format to store and handle the contents and structure of an partial or entire disk image or physical memory data.
The focus of zff is on speed, security and modularity in concert with forensic requirements.
Zff is an alternative to the ewf and aff file formats and not compatible with them.

## Features included in zff (most of them are optional)
- The disk image can be stored in several split segments.
- The data can be stored in compressed format (modern compression algorithms used, like __Zstd__)
- The stored data can be optionally encrypted with a password. Good procedures according to PKCS#5 are used here (PBKDF2-SHA256 with AES-128-CBC and AES-256-CBC is currently implemented). The encryption of the data is performed using AEAD (Authenticated Encryption with Associated Data) algorithms. Currently, AES-128-GCM-SIV and AES-256-GCM-SIV are used.
- The integrity of the stored data can optionally be ensured by using cryptographic hash values. The available hash algorithms are listed in the [hash header](#hash-header) section.
- The authenticity of the data can be additionally ensured by digital signatures. The asymmetric signature algorithm Ed25519 is used for this purpose.
- The stored data is organized in small chunks. 
Above mentioned compression, encryption and signature methods are applied to each chunk separatly. This makes it possible to access a corresponding part of the data in real time and not to have to decompress or decrypt the complete image first.
Authenticity verification can also be applied to individual chunks and does not have to be applied to the entire image.
- Modular design that promises high maintainability and scalability.

## ZFF  general layout

![alt text](https://github.com/ph0llux/zff/blob/master/assets/zff_general_layout.png?raw=true)



## Layout of main header

| Name                    |      Type         | Length in bytes | optional |
|-------------------------|:-----------------:|:---------------:|:--------:|
| Magic bytes             | 0x7A66666D        | 4               |          |
| Header length			  | uint64            | 8               |          |
| Header version          | uint8             | 1               |          |
| encryption flag         | uint8             | 1               |          |
| Encryption header       | object            | variable        | :ballot_box_with_check: |
| Compression header      | object            | variable        |          |
| Description header      | object            | variable        |          |
| Hash header             | object			  | variable        |          |
| chunk size			  | uint8			  | 1               |          |
| signature flag          | uint8			  | 1               |		   |
| Segment size		      | uint64            | 8               |          |
| Length of data in bytes | uint64            | 8               |          |
| Segment header 		  | object			  | variable        |          |

## Layout of encrypted main header

| Name                    |      Type         | Length in bytes |
|-------------------------|:-----------------:|:---------------:|
| Magic bytes             | 0x7a666645        | 4               |
| Header length in bytes  | uint64            | 8               |
| Header version          | uint8             | 1               |
| encryption flag         | uint8             | 1               |
| Encryption header       | object            | variable        |
| Encrypted data          | bytes             | variable        |

### encryption flags

| Value | description |
|-------|:-----------:|
| 0     | no encryption |
| 1     | data encryption |
| 2     | data + header encryption |

### Layout of encryption subheader

| Name                        | Type       | Length in bytes |
|-----------------------------|:----------:|:---------------:|
| Magic bytes                 | 0x7A666665 | 4               |
| Header length in bytes      | uint64     | 8               |
| Header version              | uint8      | 1               |
| PBE header                  | object     | variable        |
| Encryption algorithm        | uint8      | 1               |
| encr. encryption key length | uint32     | 4               |
| encrypted encryption key    | bytes      | variable        |
| encryption key nonce        | bytes      | 12              |

#### encryption algorithms

| Algorithm      | type value |
|----------------|:----------:|
| AES128-GCM-SIV | 0          |
| AES256-GCM-SIV | 1          |

#### Layout of password-based encryption (PBE) subheader (PCKS#5 / PBES2)

| Name                        | Type       | Length in bytes |
|-----------------------------|:----------:|:---------------:|
| Magic bytes                 | 0x7A666670 | 4               |
| Header length in bytes      | uint64     | 8               |
| Header version              | uint8      | 1               |
| KDF flag					  | uint8      | 1               |
| encryption scheme flag	  | uint8	   | 1  			 |
| KDF parameters			  | object	   | variable        |
| PBEncryption Nonce/IV 	  | bytes      | 16              |

##### KDF Flag

| Scheme         | type value |
|----------------|:----------:|
| PBKDF2/SHA256	 | 0          |

##### Encryption scheme Flag

| Scheme         | type value |
|----------------|:----------:|
| AES128CBC		 | 0          |
| AES256CBC		 | 1   		  |

##### KDF parameters

###### PBKDF2 / SHA256

| Name                        | Type       | Length in bytes |
|-----------------------------|:----------:|:---------------:|
| Magic bytes                 | 0x6b646670 | 4               |
| Header length in bytes      | uint64     | 8               |
| iterations                  | uint16     | 2               |
| salt                        | bytes      | 32              |


### Layout of compression subheader

| Name                    | Type       | Length in bytes |
|-------------------------|:----------:|:---------------:|
| Magic bytes             | 0x7A666663 | 4               |
| Header length in bytes  | uint64     | 8               |
| Header version          | uint8      | 1               |
| compression algorithm   | uint8      | 1               |
| compression level       | uint8      | 1               |

#### compression algorithms

| Algorithm | type value |
|-----------|:----------:|
| None      | 0          |
| ZSTD      | 1          |

### Layout of description subheader

| Name                   | Type       | Identifier | Required? |
|------------------------|:----------:|:----------:|:---------:|
| Magic bytes                 | 0x7A666664 | -          | :ballot_box_with_check: |
| Header length in bytes      | uint64     | -          | :ballot_box_with_check: |
| Header version              | uint8      | -          | :ballot_box_with_check: |
| Case number                 | String     | "cn"       |           |
| Evidence number             | String     | "ev"       |           |
| Examiner name               | String     | "ex"       |           |
| Notes                       | String     | "no"       |           |
| Acquisition start timestamp | uint64     | "as"       | :ballot_box_with_check: |
| Acquisition end timestamp   | uint64     | "ae"       | :ballot_box_with_check: |

### hash header

| Name                        | Type         | Length in bytes |
|-----------------------------|:------------:|:---------------:|
| Magic bytes                 | 0x7A666668   | 4               |
| Header length in bytes 	  | uint64       | 8      		   | 
| Header version         	  | uint8        | 1      		   |
| Hash values				  | Object Array | variable        |

#### Layout of hash value

| Name                        | Type         | Length in bytes | optional |
|-----------------------------|:------------:|:---------------:|:--------:|
| Magic bytes                 | 0x7a666648   | 4               |          |
| header length				  | uint64       | 8               |          |
| Header version			  | uint8        | 1               |          |
| hash type                   | uint8        | 1               |          |
| Hash 		                  | Bytes        | variable        |:ballot_box_with_check: |

##### Hash type

| Algorithm             | type value |
|-----------------------|:----------:|
| Blake2b-512 (default) | 0          |
| SHA256 	            | 1 		 |
| SHA512                | 2          |
| SHA3-256              | 3          |

### Layout of segment subheader

| Name                   |      Type         | Length in bytes |
|------------------------|:-----------------:|:---------------:|
| Magic bytes            | 0x7A666673        | 4               |
| Header length in bytes | uint64            | 8               |
| Header version         | uint8             | 1               |
| Unique identifier      | int64			 | 8               |
| Segment number         | uint64            | 8               |
| length of segment      | uint64            | 8               |

## chunk header

| Name                   |      Type         | Length in bytes | optional |
|------------------------|:-----------------:|:---------------:|:--------:|
| Magic bytes            | 0x7A666643        | 4               |		  |
| Header length in bytes | uint64            | 8               |		  |
| Header version         | uint8             | 1               |		  |
| chunk number			 | uint64			 | 8 			   |		  |
| chunk size (in bytes)  | uint64            | 8               |		  |
| CRC32					 | uint32			 | 4  			   |		  |
| ed25519 signature      | bytes			 | 64 			   |:ballot_box_with_check: |

# TODO / Wishlist
- testing / unit tests
- documentation (with deny nodoc)
- Keyfile support for encryption
- parallelism impl of hashing/crc/signing<->writing data
- impl Error handling @zffacquire if IoError->Interupt.
	-> Number of retries / sectors used as error granularity
- LZ4 compression algorithm
- Migrate HeaderEncoder/HeaderDecoder -> HeaderCoding
- data.dd impl for zffmount