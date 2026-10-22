# PHP2Shell — session UAF → 纯 HTTP RCE(PHP 8.4.4 mod_php)

[English](README.en.md) | 中文

受害者侧的全部攻击面只有一个文件:

```php
<?php echo "OK\n"; ?>
```

不需要 `session_start()`,不需要攻击类/helper 接口,不改目标 PHP 代码,不要求目标
重编译,目标上不需要 gdb,ASLR 全程开启。所有流量都是普通 HTTP:堆基址和
`libphp.so` 基址从 `Set-Cookie` 响应头里取回来,最后一个请求把一个悬空的
`zend_reference` 变成对 `zif_system` 的调用。

已验证目标:我们自己的 `PHP 8.4.4-dev` 构建(Ubuntu 24.04、Apache 2.4.58 prefork,
`libphp.so` md5 `f402b493b1df82cbf34021b4aef133cb`),镜像内直接附带该二进制,保证
标定值和被攻击的二进制永远一致。

> **本项目是衍生工作。** 利用链、阶段结构与参考实现来自
> [9bie/php2shell-bypass-aslr-exp](https://github.com/9bie/php2shell-bypass-aslr-exp),
> 见[致谢](#致谢)与[相比参考链我们解决了哪些痛点](#相比参考链我们解决了哪些痛点)。

## 一键运行

```bash
python p2s.py build            # docker build(apt 默认走中科大源)
                               # 加 --from-source 则先自己编译 mod_php
python p2s.py up               # 创建并启动全部 14 个目标容器
python p2s.py verify           # 页面内容、expose_php、libphp 偏移、worker 数
python p2s.py offsets          # 读取当前目标里的 zif_system / zval_ptr_dtor
python p2s.py exploit off      # 对某个 profile 跑 PoC -> PROOF: uid=33(www-data)
python p2s.py prune            # 回收实验状态:session 文件 + proof 文件
python p2s.py down             # 删除容器
```

`build` 一次之后,只用 `exploit <profile>` 就够:它会自动重建丢失的容器
(`ensure`)、运行前后清理过期的 session/proof 文件、打印 PoC 输出,拿不到 proof 时
返回非 0。128M 的一次利用端到端约 8 秒(2026-10-22 实测)。

环境变量:

| 变量 | 默认 | 含义 |
| --- | --- | --- |
| `APT` | `cn` | `cn` = 改写为镜像源,`off` = 保留镜像自带源,`skip` = 完全不跑 apt |
| `APT_MIRROR` | `mirrors.ustc.edu.cn` | `APT=cn` 时使用的镜像 |
| `BASE` | `ubuntu:24.04` | 基础镜像 |
| `P2S_CLEAN` | `1` | 设为 `0` 则运行后保留 session/proof 文件 |
| `exploit <p> -c '…'` | `id>/srv/out/pd` | 执行的命令;proof 路径跟随 `>/srv/out/<file>` 重定向 |

## 实验环境结构

```
p2s.py                  一键驱动(build/up/down/status/verify/offsets/exploit/prune)
docker/
  Dockerfile            ubuntu:24.04 + apache2 运行库 + 预编译 libphp.so
  Dockerfile.builder    可选:`build --from-source` 的构建依赖
  build-libphp.sh       在其中执行的 php-src 8.4.4 编译脚本
  offsets.py            nm 读取器:写出 env/generated/offsets.env 供 PoC 使用
  bin/libphp.so         标定偏移所用的 PHP 8.4.4-dev 构建
  bin/opcache.so        仅 `opc` profile 使用
  src/php-src-844.tar   对应源码,重建用(136 MB,运行实验并不需要)
  www/index.php         受害者页面 —— 22 字节,见下文坑说明
  entrypoint.sh         mkdir /srv/out,然后 `apache2 -f /srv/profile/apache.conf`
env/gen_profiles.py     14 个 profile 的唯一来源 -> env/generated/<name>/
exploits/               PoC(自包含,不含任何宿主机绝对路径)
  exploit.py            从 9bie/php2shell-bypass-aslr-exp 原样保留的参考链
  worker.py             docker exec 辅助:容器名、端口、输出目录、worker 复位
  def_rce.py            display_errors=Off 链(128M/256M/512M/1G,expose_php 两种)
  default_rce.py        display_errors=On + expose_php=Off 链
  dev_on_rce.py         display_errors=On + expose_php=On 链(cookie 告警泄漏 + On stage3)
  dev_off_rce.py        display_errors=On + expose_php=Off 且支持长命令
                        (opcache profile 也用它,靠 CMDOFF 区分)
measure/                标定与 gdb 辅助脚本(普通复现不需要)
  利用驱动              measure_dd_any.py、mw_full_test.py、measure_s3_formfill.py、
                        measure_loaded_worker.py、dev_r0.py(重测 R0)
  gdb/gdb-*.py          psdump、s3trace、heapstat、trigger —— 由上述驱动加载
tools/probe.php         可选的 webroot 探针(已加载 ini、指令、扩展)
```

每个 profile 在 `env/generated/<name>/` 下有 `php.ini`、`apache.conf`、`port`。
`p2s.py` 把该目录挂载两次 —— `/srv/profile`(给 Apache)和
`/usr/local/etc/php`(libphp 编译进二进制的 ini 路径,PHP 实际读这里的地方),
再把 `docker/www` 挂到 `/srv/www`、`out-<name>/` 挂到 `/srv/out`。
一个 profile 一个容器,全部只发布在 `127.0.0.1`。

## profile 与对应 PoC

| 别名 | 容器 | 端口 | memory_limit | display_errors | expose_php | save_path | worker | opcache | PoC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `off` | p2s-def | 8098 | 128M | Off | Off | /tmp | 1 | – | `exploits/def_rce.py` |
| `on` | p2s-on | 8099 | 128M | Off | On | /tmp | 1 | – | `exploits/def_rce.py` |
| `default` | p2s-default | 8096 | 128M | On | Off | /tmp | 1 | – | `exploits/default_rce.py` |
| `dev` | p2s-dev | 8102 | 128M | On | On | /tmp | 1 | – | `exploits/dev_on_rce.py` |
| `ub` | p2s-ub | 8103 | 128M | Off | Off | /var/lib/php/sessions | 1 | – | `exploits/def_rce.py` |
| `ub-on` | p2s-ub-on | 8104 | 128M | Off | On | /var/lib/php/sessions | 1 | – | `exploits/def_rce.py` |
| `off256` | p2s-256 | 8105 | 256M | Off | Off | /tmp | 1 | – | `exploits/def_rce.py` |
| `off512` | p2s-512 | 8106 | 512M | Off | Off | /tmp | 1 | – | `exploits/def_rce.py` |
| `off1g` | p2s-1g | 8107 | 1G | Off | Off | /tmp | 1 | – | `exploits/def_rce.py` |
| `dd256` | p2s-dd256 | 8108 | 256M | On | Off | /tmp | 1 | – | `measure/measure_dd_any.py` |
| `dd512` | p2s-dd512 | 8109 | 512M | On | Off | /tmp | 1 | – | `measure/measure_dd_any.py` |
| `dd1g` | p2s-dd1g | 8110 | 1G | On | Off | /tmp | 1 | – | `measure/measure_dd_any.py` |
| `mw` | p2s-mw | 8100 | 128M | Off | Off | /tmp | 8 | – | `measure/mw_full_test.py`(扇出) |
| `opc` | p2s-opc | 8111 | 128M | On | Off | /tmp | 1 | On | `exploits/dev_off_rce.py` + `CMDOFF=0x7a118` |

所有 profile 提供同一个 22 字节页面。`exploit <别名>` 会替你选好 PoC、堆标定
(`PROFILE`)和 proof 路径;`-s <脚本>` 覆盖脚本,`-c` 覆盖命令,结尾的数字设置
`mw` 的扇出宽度(默认取该 profile 的 `MaxRequestWorkers`)。

本树 2026-10-22 的验证结果:`p2s.py verify` 14 个容器全绿;一次连续 `exploit` 扫描
对每个 profile 都拿到 `PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)`
—— `off`、`on`、`default`、`dev`、`ub`、`ub-on`、`off256`、`off512`、`off1g`、
`dd256`、`dd512`、`dd1g`、`opc`、`mw`(对 8 个 prefork 子进程扇出)。

## 相比参考链我们解决了哪些痛点

参考链在
[9bie/php2shell-bypass-aslr-exp](https://github.com/9bie/php2shell-bypass-aslr-exp)
中的形态是:对 Debian 13 / Apache 2.4.69 上的 PHP 8.4.26 NTS、使用官方
`php.ini-production`(`display_errors=Off`、`memory_limit=128M`)、单 worker
prefork,以 A1 → B1 → A2 → B2 四步完成利用,目标页面只有 `<?php echo "OK\n"; ?>`,
单次约 2 秒。这是基线;下表是本树改动的部分,以及证明它成立的 profile。

| 参考链的痛点 | 本树的做法 | 证据 |
| --- | --- | --- |
| OOM 必须落在 cookie 的 `php_url_encode()` 路径里,也就是要求 `display_errors=Off` | 引入第二个触发器:1001 个 cookie 撞出 `max_input_vars` 告警,告警被打印即置 `headers_sent`,`php_session_send_cookie()` 失败,随后普通 body 填充在 `multipart_buffer_read_body` 里 OOM —— 于是 `display_errors=On` 也能打,而且不需要页级标定 | `default`、`dev`、`dd256/512/1g`、`opc` |
| `memory_limit` 只能保持 128M | 128M / 256M / 512M / 1G 全部打通,两个触发器各自覆盖 | `off256`、`off512`、`off1g`、`dd256`、`dd512`、`dd1g` |
| 只支持单 worker prefork(上游 README 明确说完整 worker 环境之后放出) | 每个 prefork 子进程各发一对 stage-A/B 做扇出;所有子进程 `fork()` 自同一父进程,继承同一份 chunk 与 `libphp` 基址,因此一次泄漏对整个线程池有效 | `mw`(8 个子进程,8 个 stage-B 全部执行) |
| 只覆盖一种 `expose_php` 布局 | 两种都覆盖:`R0 = chunk+0x68140`(Off)、`chunk+0x752E0`(On) | `on`、`dev`、`ub-on` |
| 只覆盖一种 `session.save_path` 布局 | save_path 长度只把 `R0` 移动 `0x20`,于是同一份载体里放置两个相邻伪引用,一个请求同时覆盖短路径与长路径 | `ub`、`ub-on`(`/var/lib/php/sessions`) |
| 未覆盖 opcache | opcache 下可打(载体移到 `CMDOFF=0x7a118`,驱动对该 profile 自动选择) | `opc` |
| 命令塞在一个很小的存活 `zend_string` 里(14 字节;更长的要靠 `sh</out/c` 两步落地) | 独立的 3100 字节 `CMD` 字段携带一个外部伪 `zend_string`(最长约 1.7 KB,含 shell 元字符),伪 `execute_data` 的 arg1 指向它 —— 一次请求,不需要预置文件 | `dev_off_rce.py`、`opc` |
| 「换 PHP 构建/版本需要重新标定偏移」,但标定工具不在交付里 | 重标定属于实验本身:`p2s.py offsets` 从运行中的目标读 `zif_system`/`zval_ptr_dtor` 写入 `env/generated/offsets.env`,`exploit` 自动以 `ZIF_OFF`/`DTOR_OFF` 注入;`R0_OFF`、`CMDOFF`、`NFILL/FILLSZ/S3_BIGLEN`、`BURN_SPEC/TAIL*` 全部可用环境变量覆盖;`measure/dev_r0.py` + `measure/gdb/` 记录每个常量的测法 | 下文「重建受害者二进制」 |
| 目标二进制只能用官方镜像自带的那份 | `build --from-source` 自己从 php-src 编译 mod_php,没有 53 MB 二进制的克隆也能自足 | 下文实测 |
| 交付形式是 `run_pure.sh` + 一个 `exploit.py` | 14 个 profile × 一条命令、`verify`/`status`/`offsets`/`prune`、proof 与脚本自动配对、被外部 `docker prune` 干掉后自愈、中英双语 README | 「一键运行」「回收」 |

## 利用链

每阶段两个请求,全部是 chunked 的 multipart/form-data。

**Stage 1 —— 制造悬空状态。** `memory_limit` 在请求启动阶段命中,此时 session 已
初始化、`php_request_shutdown` 尚未执行,于是 worker 继续持有着已经交回分配器的内存
指针。两个触发器:

* `display_errors=Off`(`def_rce`):OOM 发生在 `php_url_encode()` 转义 session id
  以生成 `Set-Cookie` 时,因为 `send_cookie` 仍为 1。要走到那里必须把整个堆精确填满到
  页边界(`BURN_SPEC` 密集 `filename=""` 上传 + `TAILB/TAILC/TAILD/BIGTAIL/…`),
  所以这条链带着一套按 `memory_limit` 分别标定的参数。
* `display_errors=On`(`default_rce`、`measure_dd_any`):1001 个 cookie 触发
  `max_input_vars` 告警,告警打印后置 `headers_sent`,`php_session_send_cookie()`
  失败,`php_session_track_init()` 被跳过;接着用普通填充(`N` 个 4MB 表单字段 + 一个
  巨大字段)在 `multipart_buffer_read_body` 里 OOM。不需要页级标定,只有填充量随
  limit 伸缩。

**Stage 1 泄漏。** 在陈旧 `PS(id)` 仍指向的那些页上放置伪造 `zend_string` 头
(`len = 0x4000`/`0x40000`),下一个请求的 `Set-Cookie: PHPSESSID=…` 就会带回最多
256 KB 堆内容。其中占主导的 2 MB 对齐基址就是 Zend MM main chunk,而每一个与
`zval_ptr_dtor` 同余的 qword 都给出 `libphp.so` 基址(即与 ASLR 无关)—— 正常一次
运行里有 31 个匹配 qword,已与 `/proc/1/maps` 对照校验。

**Stage 3 —— 执行代码。** 请求 A 用 `PHPSESSID=bbbb…` +
`PHP_SESSION_UPLOAD_PROGRESS` 重放触发器,于是 `php_session_track_init()` 在已知
chunk 偏移(`R0`)处分配 session 的 `zend_reference`,随后请求死掉,留下
`PS(http_session_vars)` 悬空。请求 B 喷入一个正好落在 `R0` 上的值,内含伪
`zend_reference`(`rc=1`、`type=0x1a`),其 `val.value` 指向 `R0+0x28` 处的伪
`HashTable`,`pDestructor = zif_system`。于是
`zend_reference_destroy` → `zend_array_destroy` → `zend_hash_destroy` → `system(cmd)`。

`session.save_path` 长度只会让 `R0` 偏移 `0x20`,所以载体里放两个相邻伪引用,一个
请求同时覆盖两类路径(`/tmp` 与长路径)。命令不是 14 字节内联串:独立的 3100 字节
`CMD` 字段携带外部伪 `zend_string`(最长约 1.7 KB,含 shell 元字符),伪
`execute_data` 的 arg1 指向它。

## 常量

| 项目 | 值 |
| --- | --- |
| `zif_system` | `libphp + 0x457FE0` |
| `zval_ptr_dtor` | `libphp + 0x64B890` |
| `R0`(expose_php=Off) | `chunk + 0x68140` |
| `R0`(expose_php=On) | `chunk + 0x752E0` |
| 伪 HashTable | `R0 + 0x28`(或 `CMD` 副本固定位于 `chunk + CMDOFF + 0x700`) |
| `CMDOFF` | Off 为 `0x83118`,On 为 `0x84118`,opcache 下 `0x7a118` |
| chunk 大小 | `0x200000`(`ZEND_MM_CHUNK_SIZE`) |

PoC 需要从目标拿到的只有每次运行泄漏出的 `chunk` 与 `libphp` 基址,所以 ASLR 和容器
重启都不影响。*不可*移植的是请求形态:`R0`、填充数量、`CMDOFF` 是这个构建、这份
`php.ini` 与这个受害者页面的属性。`measure/` 保存了得到它们的 gdb 驱动
(`measure/gdb/gdb-psdump.py` 在 stage-A 之后读取陈旧的 `PS()` 全局变量,
`measure/gdb/gdb-s3trace.py` 跟踪
`track_init → reference_destroy → hash_destroy → zif_system`),
`measure/dev_r0.py` 演示如何为新布局重测 `R0`。`def_rce.py` 支持从环境变量读
`BURN_SPEC/TAILB/TAILC/TAILD/DUPNAMES/CMDOFF/R0_OFF/NFILL/FILLSZ/S3_BIGLEN`,
重测之后不需要改代码。

## 受害者条件

硬性条件:PHP 8.4.x mod_php(prefork)、`session.upload_progress.enabled=On` 且
`.cleanup=On`、`session.use_cookies=On`、`session.use_strict_mode=Off`、`files`
save handler 且 `save_path` 可写、`memory_limit` 可被填充打满。
已经不再是条件:`display_errors`(两种)、`expose_php`(两种)、
`session.save_path` 长度(两种)、`memory_limit`(128M/256M/512M/1G)、
`max_input_vars=1000` / `max_multipart_body_parts=-1`(出厂默认)、ASLR、
opcache(`opc` profile 用的是 `display_errors=On` 触发器 + `CMDOFF=0x7a118`)、
多 worker 线程池(扇出)。
真实世界的阻碍:Apache 前面的流量限制(饱和式 `display_errors=Off` 的 stage-1 A
body 很小、约 1–2 MB,但会吃掉整个 `memory_limit` 的堆;`display_errors=On` 触发器
把填充放在 body —— 128M 约 136 MB、1G 约 1.3 GB;`off1g` 的 stage-3 A 同样要流
1.3 GB 填充)、会截断 `Set-Cookie` 泄漏的头大小限制,以及同一阶段两个请求之间任何
堆活动 —— 两个请求必须打到同一个子进程,所以单 worker profile 钉住
`MaxRequestWorkers=1`,而 `mw` 则按线程池大小扇出(默认宽度 = 该 profile 的
`MaxRequestWorkers`,可用 `MWN` 或命令行结尾数字覆盖)。所有子进程都 `fork()` 自同一
父进程,共享同一份 chunk 与 `libphp` 基址,一次泄漏就够。

## 回收

* `p2s.py prune [profile…]` 删除每个容器内的 `/tmp/sess_*` 与 `/srv/out/*`,以及宿主
  侧对应 `out-<profile>/` 里的文件。`exploit` 每次运行前都会清理,结束后再次清 session
  文件(`P2S_CLEAN=1`):残留 session 会让下一次 `s_read` 提前 OOM,残留 proof 会让失败
  看起来像成功。proof 文件本身保留作为证据。
* `p2s.py down [profile…]` 删除容器;`docker rmi p2s-php844` 删除镜像。除本实验目录
  之外不触碰任何东西。
* `exploit`/`verify` 会自动重建消失的容器(外部 `docker prune`、daemon 重启),而不是
  抛连接错误。
* stage-3 B *预期*会打死子进程:Apache 父进程会 fork 新的,而泄漏出的基址因为
  `fork()` 继承关系仍然有效。如果父进程本身死了,泄漏就作废 —— 先
  `p2s.py up <profile>` 再重试。

## 重建受害者二进制

优先使用自带的 `docker/bin/libphp.so`:上面每个常量都是在这个文件上测出来的
(md5 `f402b493b1df82cbf34021b4aef133cb`)。新克隆不会带这 53 MB,所以可以自己编译:

```bash
python p2s.py build --from-source                  # 使用 docker/src/php-src-844.tar
python p2s.py build --from-source --src <php-src>  # 先对该 checkout 执行 git archive
```

`--from-source` 会构建 `docker/Dockerfile.builder`(ubuntu + 校准二进制真正链接的那些
`-dev` 包),把源码 tar 以 bind mount 挂进 `p2s-srcbuild` 容器并运行
`docker/build-libphp.sh`,产物先落在 `docker/staged/`:

* 若 `docker/bin/libphp.so` 不存在 → 直接安装到那里(已有时先备份成
  `libphp.so.calibrated`)。
* 若已存在 → 保留校准版;手工替换,或用 `--install` / `P2S_INSTALL=1`。
* `docker/src/php-src-844.tar` 与分支 `PHP-8.4.4` 的 `git archive HEAD` **字节完全一致**,
  所以它永远不需要提交。

之后 `python p2s.py offsets` 从运行中的容器读出*符号*偏移
(`docker/offsets.py` → `env/generated/offsets.env`),`exploit` 自动以
`ZIF_OFF`/`DTOR_OFF` 取用,重建后不需要手改 `zif_system` / `zval_ptr_dtor`。

重建不能白拿的是堆布局:`R0_OFF`、`CMDOFF` 和填充数量是这个构建 + 这份 `php.ini` +
这个受害者页面的属性,只能用 gdb 对着活着的子进程测:

```bash
python measure/dev_r0.py            # -> R0_OFF;CMDOFF/填充见上文「常量」
python p2s.py verify && python p2s.py exploit off   # 最省事的存活证明
```

2026-10-22 本树实测:`build --from-source` 产出的二进制 md5 为
`46ab96e6f85aecac36c4c4aafd5c5cd8`(**并非**字节一致 —— 构建目录与 DWARF 不同),
但 `zif_system=0x457fe0`、`zval_ptr_dtor=0x64b890` 保持不变;换上它之后 `off`、
`default`、`ub`、`opc` 四条链仍然全部拿到 `PROOF: uid=33(www-data)`,且
`R0=chunk+0x68140`、`htdata=chunk+0x83818`(即 `CMDOFF+0x700`)与标定值一致。
结论:同源码、同 configure、同包版本 ⇒ 标定可以活过重建。实验环境仍然保持校准文件,
因为其余 10 个 profile 没有对重建版重跑。

手工编译请使用下面这条 configure 命令(校准二进制就是用它构建的 ——
`strings docker/bin/libphp.so | grep './configure'` 可以还原,容器里 `php -i` 也显示
同一行):

```
'./configure' '--with-apxs2=/usr/bin/apxs2' '--with-config-file-path=/usr/local/etc/php'
  '--with-mhash' '--enable-mbstring' '--enable-mysqlnd' '--with-password-argon2' '--with-sodium'
  '--with-pdo-sqlite=/usr' '--with-sqlite3=/usr' '--with-curl' '--with-iconv' '--with-openssl'
  '--with-readline' '--with-zlib' '--enable-opcache' '--disable-cgi' '--disable-phpdbg' '--with-pic'
```

`--with-config-file-path=/usr/local/etc/php` 正是 `ensure`/`create` 把 profile 目录同时
挂到 `/srv/profile` 和那里的原因。`--with-readline` 链接 GNU readline(用
`libedit-dev` 会产出不同二进制,而 `--with-apxs2` 需要 `apache2-bin` 提供
`/usr/sbin/apache2`);多装一个 `-dev` 包(libzip、libicu……)会静默启用某个扩展并把堆
布局挪走 —— 所以 builder 镜像只装
`objdump -p docker/bin/libphp.so | grep NEEDED` 里出现的那些。

## 踩过的坑

* `docker/www/index.php` 必须与校准时的页面字节一致
  (`<?php echo "OK\n"; ?>` + 换行,**22 字节** —— 是真正的反斜杠 n,不是渲染出的换行)。
  用 `echo` 写文件会得到 21 字节的页面,启动期分配整体偏移一字节,`expose_php=On` 的
  stage3 会静默打不到 `R0`。
* 用 `apache2 -f <conf>` 时这个构建忽略 `PHPIniDir`;ini 必须放在编译进二进制的默认
  路径,因此才有 `/usr/local/etc/php` 的双重挂载。
* 镜像附带预编译 `libphp.so`,因为标定偏移只对字节一致的二进制成立;没有 53 MB 二进制
  时用 `build --from-source`(见上一节)。
* 绝不要在 stage-A 请求过程中挂带断点的 gdb:`SIGKILL` 掉 gdb 会在 `libphp.so` 里留下
  `int3` 字节(包括被内联的 `php_session_send_cookie`),之后每次运行都会被破坏。
  只读批处理探针(`-batch -p PID -x measure/gdb/gdb-psdump.py`,不设断点)是安全的。
* Git Bash 里给 `docker exec`/`docker cp` 加 `MSYS_NO_PATHCONV=1` 前缀,否则 `/usr/...`
  参数会被改写成 Windows 路径。
* 14 个容器 + 1 GB 填充非常吃虚拟机内存;如果 Docker Desktop 开始杀容器,改用
  `p2s.py up <子集>`。

## 整理时从原目录删掉的内容

原工作目录约有 330 个文件。这里删掉了:废弃的基于 `hash_update` 的链
(`api/`、`fixed/`、`minimal/`、`reseed/`、`stale/`)、另一个 agent 的 git clone
(`ref_remote/`,44 MB)、抓下来的 Calif 报告(`calif-php2shell.html/.txt`)、被取代的
8094 三段式 `full_rce.py`,以及需要提高 `max_input_vars`/`max_multipart_body_parts`
且偏移已过期的 `off_rce.py`、一次性的 `off_a*.py` / `measure_def_ab.py` 标定驱动、
约 50 个 `gdb-*.txt` 终端记录,以及所有 `out-*` 运行产物。
保留:四个 PoC 加原样保留的参考实现 `exploit.py`、记录了每个常量*如何*测得的 gdb
驱动脚本,以及这些驱动加载的四个 `gdb-*.py`。

本交付只做 mod_php 这一条链。php-fpm/nginx(SAPI 路径完全不同的另一条链,探测脚本
为 `fpm/` 下的自制 fpm 镜像 `Dockerfile`、`php-fpm.conf`、`fcgi.py`、`bg_fpm.py` 与
整套 `gdb-bg*.py` 探针)仍在内部推进,这些脚本不在本仓库,也不计划公开。

## 致谢

* [9bie/php2shell-bypass-aslr-exp](https://github.com/9bie/php2shell-bypass-aslr-exp)
  —— 本工作的源头。mod_php 请求可以在 session 已初始化之后因 OOM bailout,而这个
  bailout 仍能被骗出一次越界 `Set-Cookie` 泄漏;泄漏里同时带着 Zend MM chunk 基址和
  `libphp.so` 基址(这正是本链在此场景下绕过 ASLR 的关键);
  `session.upload_progress` + `PHP_SESSION_UPLOAD_PROGRESS` 是把伪
  `zend_reference` 打过去的分配点 —— 这些洞见都是他们的,包括
  `<?php echo "OK\n"; ?>` 这个最小攻击面和 A1/B1/A2/B2 的阶段结构。
  本树里的 `exploits/exploit.py` 就是他们的链,作为参考实现原样保留(只修了两个本树内
  的路径)。没有那个项目,这里的一切都不存在。
* PHP 漏洞本身(session bailout 背后的 UAF)属于上游;本实验是对其可利用性的研究,
  全部只针对本实验自己创建的容器。

## 许可与使用范围

这里的一切只针对本实验在 `127.0.0.1` 创建的容器。仅用于你自己拥有或已获得授权的系统。
