# zff

## ZFF Layout

![alt text](https://github.com/ph0llux/zff/blob/master/assets/zff_general_layout.png?raw=true)

### Layout of main header

| Name                    |      Type         | Length in bytes |
|-------------------------|:-----------------:|:---------------:|
| Magic bytes             | 0x7A66666d        | 4               |
| Header length in bytes  | uint64            | 8               |
| Header version          | uint8             | 1               |
| description header      | object            | variable        |
| split size in bytes     | uint64            | 8               |
| length of data in bytes | uint64            | 8               |

#### Layout of description header

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

#### Layout of encryption header

todo.

#### Layout of split header

| Name                   |      Type         | Length in bytes |
|------------------------|:-----------------:|:---------------:|
| Magic bytes            | 0x7A666673        | 4               |
| Header length in bytes | uint64            | 8               |
| Header version         | uint8             | 1               |
| Unique identifier      | uint64			 | 8               |
| split number           | uint64            | 8               |
| length of split        | uint64            | 8               |