---
name: file-access-vuln
description: >-
  Entry P1 category router for file access and upload workflows. Use when
  testing download endpoints, file paths, local file inclusion, upload flows,
  preview pipelines, archive extraction, or storage and sharing boundaries.
---

# File Access Router

这是文件系统、下载接口、上传链路与文件预览处理的分类入口。

## When to Use

- 参数、文件名、下载接口或导入流程会影响文件路径
- 目标支持上传、预览、转码、解压、分享、下载或代理文件访问
- 你需要判断当前更偏向路径穿越、LFI，还是上传验证与处理链问题

## Skill Map

- [Path Traversal LFI](../path-traversal-lfi/SKILL.md): 路径穿越、文件读取、wrapper、包含链
- [Upload Insecure Files](../upload-insecure-files/SKILL.md): 上传校验、存储路径、处理链、覆盖、预览与分享边界

## Recommended Flow

1. 先看入口是路径参数、下载接口还是上传流程
2. 再看问题出现在 accept、store、process、serve 哪一段
3. 小样本路径链和上传绕过样本已经并入主专题 skill，不再单独走 payload 入口

## Related Categories

- [injection-checking](../injection-checking/SKILL.md)
- [business-logic-vuln](../business-logic-vuln/SKILL.md)