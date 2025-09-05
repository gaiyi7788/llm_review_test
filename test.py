#!/usr/bin/env python3
"""
增强版 Hello World 测试文件 - 用于 LLM 静态扫描测试

这个文件包含各种常见的代码模式、潜在安全问题和质量问题，
用于测试静态分析工具的能力。
"""

import os
import sys
import json
import subprocess
import pickle
import hashlib
import logging
import re
import sqlite3
from typing import Optional, List, Dict, Any
from datetime import datetime

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


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


def security_vulnerability_examples():
    """
    安全漏洞示例函数 - 用于测试安全扫描
    """
    # 1. 硬编码密码（测试安全扫描）
    database_password = "super_secret_password_123"  # 这应该被扫描器检测到
    api_key = "sk_live_1234567890abcdef"  # 模拟API密钥泄漏
    
    # 2. 命令注入漏洞
    user_input = "echo malicious_code"  # 模拟用户输入
    # 危险的使用方式（应被检测）
    os.system(f"ls -la {user_input}")
    subprocess.call(f"echo {user_input}", shell=True)
    
    # 3. SQL注入漏洞（模拟）
    user_id = "1; DROP TABLE users; --"
    query = f"SELECT * FROM users WHERE id = {user_id}"  # 危险拼接
    
    # 4. 反序列化漏洞（pickle不安全使用）
    malicious_data = b"cos\nsystem\n(S'rm -rf /'\ntR."  # 模拟恶意pickle数据
    try:
        pickle.loads(malicious_data)  # 危险的反序列化
    except:
        pass
    
    return database_password


def code_quality_issues():
    """
    代码质量问题示例函数
    """
    # 1. 未使用的变量和导入
    unused_variable = "This is never used"  # 应被检测
    
    # 2. 重复代码
    result1 = 10 + 5
    result2 = 10 + 5  # 重复计算
    
    # 3. 过长的函数（模拟）
    x = 1
    y = 2
    z = 3
    a = 4
    b = 5  # 多个变量声明，可能提示函数过长
    
    # 4. 魔法数字
    timeout = 300  # 应该定义为常量
    max_retries = 3  # 魔法数字
    
    # 5. 复杂的条件判断
    if (x > 1 and y < 10) or (z == 3 and a != 4) or b == 5:
        pass
    
    return result1 + result2


def resource_management_examples():
    """
    资源管理示例函数
    """
    # 1. 文件操作（可能存在的资源泄漏）
    # 不安全的方式（没有使用with语句）
    file = open("test.txt", "w")
    file.write("test content")
    # 这里应该有关闭操作，但被"忘记"了
    
    # 2. 数据库连接（模拟资源泄漏）
    conn = None
    try:
        conn = sqlite3.connect(":memory:")
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE test (id INTEGER, name TEXT)")
        # 这里应该有关闭操作
    except Exception as e:
        logger.error(f"Database error: {e}")
    
    return conn  # 返回未关闭的连接


def input_validation_examples(user_input: str):
    """
    输入验证示例函数
    """
    # 1. 缺乏输入验证
    # 直接使用用户输入（危险）
    processed_input = user_input.lower()
    
    # 2. 正则表达式验证（可能存在问题）
    # 过于宽松的验证
    if re.match(r".*", user_input):  # 匹配任何输入
        print("Input accepted")
    
    # 3. 类型转换缺乏错误处理
    try:
        number = int(user_input)  # 可能抛出ValueError
    except ValueError:
        number = 0
    
    return processed_input, number


def cryptographic_examples():
    """
    密码学相关示例函数
    """
    # 1. 弱哈希算法（MD5）
    password = "user_password"
    weak_hash = hashlib.md5(password.encode()).hexdigest()  # 不安全的哈希
    
    # 2. 硬编码加密密钥
    encryption_key = "my_secret_key_123"  # 应该从安全配置中获取
    
    # 3. 不安全的随机数（模拟）
    import random
    insecure_token = random.randint(0, 1000)  # 对于安全用途不够随机
    
    return weak_hash, encryption_key, insecure_token


def performance_issues():
    """
    性能问题示例函数
    """
    # 1. 低效的字符串拼接
    result = ""
    for i in range(100):  # 在循环中拼接字符串
        result += str(i)
    
    # 2. 不必要的计算重复
    data = [1, 2, 3, 4, 5]
    total = sum(data)
    average = total / len(data)  # 好的做法
    average_again = sum(data) / len(data)  # 重复计算sum(data)
    
    # 3. 大型数据结构的不当使用
    large_list = list(range(10000))  # 创建大型列表
    if 9999 in large_list:  # O(n)操作，对于大列表较慢
        pass
    
    return result, average, average_again


def exception_handling_examples():
    """
    异常处理示例函数
    """
    # 1. 过于宽泛的异常捕获
    try:
        risky_operation = 1 / 0  # 肯定会抛出ZeroDivisionError
    except:  # 过于宽泛，应该指定具体异常类型
        pass
    
    # 2. 异常信息泄漏（模拟）
    try:
        config = json.loads("invalid json")
    except json.JSONDecodeError as e:
        error_message = f"Failed to parse config: {e}"  # 可能泄漏敏感信息
        logger.error(error_message)
    
    # 3. 空的异常处理
    try:
        os.path.exists("/nonexistent/path")
    except Exception:
        pass  # 静默忽略异常
    
    return error_message


def dependency_injection_example(service):
    """
    依赖注入示例 - 测试代码结构分析
    """
    # 良好的设计模式
    return service.process_data()


def complex_data_structures():
    """
    复杂数据结构示例
    """
    # 嵌套数据结构
    complex_config = {
        "server": {
            "host": "localhost",
            "port": 8080,
            "ssl": {
                "enabled": True,
                "certificate": "/path/to/cert.pem"
            }
        },
        "database": {
            "connection_string": "sqlite:///test.db",
            "pool_size": 10
        }
    }
    
    # 使用生成器表达式
    large_data = (x for x in range(1000000))  # 生成器，节省内存
    
    return complex_config, large_data


def main():
    """主函数 - 集成所有测试示例"""
    print("=== LLM 静态扫描测试文件 ===")
    
    # 基本功能测试
    print(hello_world())
    print(hello_world("LLM Scanner"))
    
    # 安全漏洞测试
    security_vulnerability_examples()
    
    # 代码质量测试
    code_quality_issues()
    
    # 密码学测试
    cryptographic_examples()
    
    # 性能问题测试
    performance_issues()
    
    # 异常处理测试
    exception_handling_examples()
    
    # 复杂数据结构测试
    complex_data_structures()

    return 0


if __name__ == "__main__":
    # 系统退出代码
    sys.exit(main())