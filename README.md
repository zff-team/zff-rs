# zff

## ZFF Layout

![alt text](https://github.com/ph0llux/zff/blob/master/assets/zff_general_layout.png?raw=true)

### Layout of main header

| Name                |      Type         | Length in bytes |
|---------------------|:-----------------:|:---------------:|
| Magic bytes         | 0x7A6666          | 3               |
| Header version      | uint8             | 1               |
| description header  | object            | variable        |
| split size in bytes | uint64            | 8               |
| length of data      | uint64            | 8               |

#### Layout of description header

| Name                  | Type       | Identifier | Required? |
|-----------------------|:----------:|:----------:|:---------:|
| Header version        | uint8      | 1          | :ballot_box_with_check: |
| Case number           | String     | "cn"       |           |
| Evidence number       | String     | "ev"       |           |
| Examiner name         | String     | "ex"       |           |
| Notes                 | String     | "no"       |           |
| Acquisition date/time | uint32     | "ad"       |           |
| System date/time      | uint32     | "sd"       |           |

#### Layout of encryption header

todo.

#### Layout of split header

| Name                |      Type         | Length in bytes |
|---------------------|:-----------------:|:---------------:|
| Magic bytes         | 0x7A666673        | 4               |
| Unique identifier   | uint64			  | 8               |
| split number        | uint64            | 8               |
| length of split     | uint64            | 8               |