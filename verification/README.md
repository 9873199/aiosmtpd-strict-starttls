本目录保留aiosmtpd严格STARTTLS边界的独立验收。实际环境为Windows、Python 3.14.3，未容器化，只用本机回环和临时证书，不需要外部邮件服务。具体依赖、真实模块导入位置见environment-reviewed.json。请按verification/reproduction-notes.md安装记录版本，PYTHONPATH指向检出的冻结仓库；执行JSON中本机绝对路径替换为当前检出及验证目录。有效独立验收为acceptance-r2，16通过、HELO用例1失败，保留了最初夹具同步问题及原回归套接字错误，不将其计为模型缺陷。模型原轨测试、独立验收和录屏中的重复运行分别列证，不混算。原生轨迹和75秒视频仅在各自飞书附件字段，不在这里复制。

冻结产物提交：https://github.com/9873199/aiosmtpd-strict-starttls/commit/021d27ce0dcf407f47808614b2234851532c4e24
这些独立验收文件在模型首轮结束后生成，不是模型原轨中的测试。
