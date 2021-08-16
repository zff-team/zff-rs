# zff

## ZFF  general gayout

![alt text](https://github.com/ph0llux/zff/blob/master/assets/zff_general_layout.png?raw=true)

## Layout of main header

| Name                    |      Type         | Length in bytes |
|-------------------------|:-----------------:|:---------------:|
| Magic bytes             | 0x7A66666d        | 4               |
| Header length in bytes  | uint64            | 8               |
| Header version          | uint8             | 1               |
| encryption flag         | uint8             | 1               |
| Encryption header       | object            | variable        |
| Compression header      | object            | variable        |
| Description header      | object            | variable        |
| Split size in bytes     | uint64            | 8               |
| Length of data in bytes | uint64            | 8               |

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
| AES Nonce/IV 				  | bytes      | 16              |

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

| Name           | Type       | Length in bytes |
|----------------|:----------:|:---------------:|
| iterations     | uint16     | 2               |
| salt           | bytes      | 32              |


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
| Magic bytes            | 0x7A666664 | -          | :ballot_box_with_check: |
| Header length in bytes | uint64     | -          | :ballot_box_with_check: |
| Header version         | uint8      | -          | :ballot_box_with_check: |
| Case number            | String     | "cn"       |           |
| Evidence number        | String     | "ev"       |           |
| Examiner name          | String     | "ex"       |           |
| Notes                  | String     | "no"       |           |
| Acquisition date/time  | uint32     | "ad"       |           |

### Layout of encryption subheader

todo.

### Layout of split subheader

| Name                   |      Type         | Length in bytes |
|------------------------|:-----------------:|:---------------:|
| Magic bytes            | 0x7A666673        | 4               |
| Header length in bytes | uint64            | 8               |
| Header version         | uint8             | 1               |
| Unique identifier      | uint64			 | 8               |
| split number           | uint64            | 8               |
| length of split        | uint64            | 8               |