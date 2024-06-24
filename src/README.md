准备Ubuntu20 64位操作系统，执行命令如下：
```bash
pip3 install angr==9.0.4495
sudo apt-get install graphviz graphviz-dev
pip3 install pygraphviz
```

上述安装过程中可能出现某些模块找不到的错误，只需要用pip3安装这些模块即可解决。
最后在项目主文件夹执行python3 rdCode.py -i mips_test命令即可。

```bash
python3 rdCode.py -i [binary_file_name]
```

