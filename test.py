#!/usr/bin/env python3
"""
Hello World 测试文件 - 用于 LLM 静态扫描测试

这个文件包含各种常见的代码模式和潜在问题，
用于测试静态分析工具的能力。
"""

import os
import sys
from typing import Optional


def hello_world(name: Optional[str] = None) -> str:
    """
    一个简单的问候函数，包含多种代码模式用于测试。
    
    Args:
        name: 可选的名称参数
        
    Returns:
        问候字符串
    """
    # 基本字符串操作
    if name is None:
        greeting = "Hello, World!"
    else:
        greeting = f"Hello, {name}!"
    
    # 简单的循环和条件判断
    for i in range(3):
        if i % 2 == 0:
            print(f"Counting: {i}")
    
    # 列表推导式
    numbers = [x * 2 for x in range(5)]
    
    # 字典操作
    config = {
        "debug": True,
        "version": "1.0",
        "features": ["scan", "test", "analyze"]
    }
    
    return greeting


def potential_issue_example():
    """
    包含一些可能的问题模式用于静态扫描测试。
    """
    # 硬编码密码（测试安全扫描）
    test_password = "password123"  # 这应该被扫描器检测到
    
    # 未使用的变量
    unused_var = "This is not used"
    
    # 可能的除零错误
    denominator = 0
    if denominator != 0:  # 防御性检查
        result = 10 / denominator
    
    return test_password


class TestClass:
    """一个简单的测试类"""
    
    class_variable = "class_value"
    
    def __init__(self, value: str):
        self.instance_value = value
    
    def get_value(self) -> str:
        """获取实例值"""
        return self.instance_value
    
    @classmethod
    def class_method(cls) -> str:
        """类方法示例"""
        return cls.class_variable


def main():
    """主函数"""
    # 基本功能测试
    print(hello_world())
    print(hello_world("LLM Scanner"))
    
    # 类使用测试
    test_obj = TestClass("test_value")
    print(test_obj.get_value())
    print(TestClass.class_method())
    
    # 环境变量访问（测试权限扫描）
    home_dir = os.getenv("HOME")
    if home_dir:
        print(f"Home directory: {home_dir}")
    
    print("ssssssssssss")
    
    return 0


if __name__ == "__main__":
    # 系统退出代码
    sys.exit(main())
