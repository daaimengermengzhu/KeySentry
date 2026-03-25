#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
  KeySentry - API密钥安全扫描工具
  版本: 1.0
  用途: 扫描项目中的API密钥泄露风险，提供安全建议
  作者: KeySentry Team
=============================================================================

老板，这份代码我加了详细的中文注释，方便您审计！

使用方法:
  python sentry.py          # 扫描当前目录
  python sentry.py /path    # 扫描指定目录
"""

import os
import re
import sys
from pathlib import Path


# ============================================================================
# 第一部分：配置区域
# 这里定义了扫描的规则和文件类型
# ============================================================================

# 需要扫描的文件扩展名列表
# 包含常见的代码文件和配置文件
TARGET_EXTENSIONS = {'.py', '.js', '.ts', '.env', '.json', '.yaml', '.yml', '.toml', '.cfg', '.ini', '.conf', '.pth'}

# 平台密钥特征识别规则
# 用于判断泄露的密钥属于哪家平台
PLATFORM_SIGNATURES = {
    'sk-': {
        'name': 'OpenAI / DeepSeek / 通用格式',
        'url': 'https://platform.openai.com/api-keys',
        'deepseek_url': 'https://platform.deepseek.com/api_keys',
    },
    'sk-proj-': {
        'name': 'OpenAI Project Key',
        'url': 'https://platform.openai.com/api-keys',
    },
    'gsk_': {
        'name': 'Groq (极速推理)',
        'url': 'https://console.groq.com/keys',
    },
    'xai-': {
        'name': 'xAI (Grok)',
        'url': 'https://console.x.ai/',
    },
}

# API密钥的正则表达式规则
# 匹配多种格式的API密钥
# 这个规则覆盖了 OpenAI、DeepSeek、小米、Groq、xAI、Anthropic、Google、Mistral等厂商的格式
API_KEY_PATTERN = re.compile(
    r'(sk-[a-zA-Z0-9]{32,})|'  # sk- 开头，后面32位以上的字母数字（OpenAI、DeepSeek等）
    r'(sk-proj-[a-zA-Z0-9_-]{20,})|'  # sk-proj- 开头（OpenAI Project Key）
    r'(sk-ant-[a-zA-Z0-9]{20,})|'  # sk-ant- 开头（Anthropic Claude）
    r'(gsk_[a-zA-Z0-9]{32,})|'  # gsk_ 开头，后面32位以上的字母数字（Groq）
    r'(xai-[a-zA-Z0-9]{20,})|'  # xai- 开头，后面20位以上的字母数字（xAI Grok）
    r'(AIza[a-zA-Z0-9_-]{35,})|'  # AIza 开头（Google Gemini）
    r'(mistral-[a-zA-Z0-9]{20,})',  # mistral- 开头（Mistral AI）
    re.IGNORECASE               # 忽略大小写
)

# 需要忽略的目录（常见的第三方库和缓存目录）
IGNORE_DIRS = {
    'node_modules',      # Node.js 依赖目录
    '__pycache__',       # Python 缓存目录
    '.git',              # Git 版本控制目录
    'venv',              # Python 虚拟环境
    'env',               # 环境变量目录
    '.venv',             # 虚拟环境（点号开头）
    'dist',              # 构建输出目录
    'build',             # 构建输出目录
    '.idea',             # JetBrains IDE 配置
    '.vscode',           # VS Code 配置
}

# ============================================================================
# 供应链攻击检测规则
# 针对 LiteLLM 等 AI 基础设施供应链漏洞的检测
# ============================================================================

# 可疑的 .pth 文件名（供应链攻击常见载体）
SUSPICIOUS_PTH_FILES = {
    'litellm_init.pth',   # LiteLLM 相关的可疑 .pth 文件
}

# 供应链攻击特征：环境变量窃取 + 网络外发组合
SUPPLY_CHAIN_ATTACK_PATTERN = re.compile(
    r'os\.environ|'                           # 访问环境变量
    r'os\.getenv|'                            # 获取环境变量
    r'requests\.post|'                        # 网络外发 POST
    r'requests\.get|'                         # 网络外发 GET
    r'urllib\.request|'                       # URL 请求
    r'http\.client|'                          # HTTP 客户端
    r'socket\.connect',                       # Socket 连接
    re.IGNORECASE
)

# 危险的网络外发目标模式（不明 IP 或可疑域名）
SUSPICIOUS_NETWORK_PATTERN = re.compile(
    r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # 直接 IP 地址
    r'https?://[a-z0-9.-]+\.tk/|'                      # .tk 域名
    r'https?://[a-z0-9.-]+\.ml/|'                      # .ml 域名
    r'https?://[a-z0-9.-]+\.ga/|'                      # .ga 域名
    r'https?://[a-z0-9.-]+\.cf/|'                      # .cf 域名
    r'https?://[a-z0-9.-]+\.gq/|'                      # .gq 域名
    r'pastebin\.com|'                                  # Pastebin
    r'telegram\.org|'                                  # Telegram
    r'discord\.com/api/webhooks',                      # Discord Webhook
    re.IGNORECASE
)


# ============================================================================
# 第二部分：扫描引擎
# 这里实现了核心的文件扫描逻辑
# ============================================================================

class SentryScanner:
    """
    KeySentry 扫描器类
    
    这个类负责：
    1. 递归遍历目录，找到所有目标文件
    2. 逐行扫描文件内容，匹配API密钥
    3. 检查 .gitignore 是否保护了 .env 文件
    4. 检测供应链攻击特征（LiteLLM 类漏洞）
    5. 生成可视化安全报告
    """
    
    def __init__(self, target_dir='.'):
        """
        初始化扫描器
        
        参数:
            target_dir: 要扫描的目标目录，默认为当前目录
        """
        # 把目标目录转换成绝对路径，方便后续显示
        self.target_dir = os.path.abspath(target_dir)
        
        # 扫描结果统计
        self.scanned_files_count = 0  # 已扫描的文件数量
        self.found_risks = []         # 发现的 API Key 泄露风险列表
        self.supply_chain_risks = []  # 发现的供应链攻击风险列表
        
        # 工程红线检查结果
        self.gitignore_exists = False    # .gitignore 是否存在
        self.env_in_gitignore = False    # .gitignore 是否包含 .env
    
    def scan(self):
        """
        执行完整的安全扫描流程
        
        这是主入口方法，按顺序执行：
        1. 工程红线检查（检查 .gitignore）
        2. 深度指纹扫描（扫描API密钥）
        3. 生成可视化报告
        """
        print("=" * 70)
        print("  🛡️  KeySentry - API密钥安全扫描工具 v1.0")
        print("=" * 70)
        print(f"  📁 扫描目录: {self.target_dir}")
        print("=" * 70)
        print()
        
        # 第一步：检查工程红线
        self._check_gitignore()
        
        # 第二步：执行深度扫描
        self._scan_directory(self.target_dir)
        
        # 第三步：生成报告
        self._generate_report()
    
    def _check_gitignore(self):
        """
        工程红线检查：检查 .gitignore 文件
        
        为什么这个检查很重要？
        - .env 文件通常包含数据库密码、API密钥等敏感信息
        - 如果 .env 被提交到 Git 仓库，所有协作者都能看到这些密钥
        - 正确的做法是在 .gitignore 中排除 .env 文件
        """
        gitignore_path = os.path.join(self.target_dir, '.gitignore')
        
        # 检查 .gitignore 文件是否存在
        if os.path.exists(gitignore_path):
            self.gitignore_exists = True
            
            # 读取 .gitignore 内容
            try:
                with open(gitignore_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                # 检查是否包含 .env
                # 这里用简单的字符串匹配，因为 .gitignore 的规则比较固定
                # 匹配以下几种情况：
                #   .env          （精确匹配）
                #   .env.*        （匹配 .env.local 等）
                #   *.env         （通配符匹配）
                if '.env' in content or '*.env' in content:
                    self.env_in_gitignore = True
            except Exception as e:
                # 如果读取失败，不影响其他扫描
                print(f"  ⚠️  读取 .gitignore 失败: {e}")
    
    def _scan_directory(self, directory):
        """
        递归扫描目录下的所有目标文件
        
        参数:
            directory: 要扫描的目录路径
        """
        try:
            # 遍历目录下的所有条目
            for entry in os.scandir(directory):
                # 获取完整路径
                full_path = entry.path
                
                # 如果是目录
                if entry.is_dir():
                    # 检查是否在忽略列表中
                    if entry.name not in IGNORE_DIRS:
                        # 递归扫描子目录
                        self._scan_directory(full_path)
                
                # 如果是文件
                elif entry.is_file():
                    # 获取文件扩展名
                    _, ext = os.path.splitext(entry.name)
                    
                    # 检查是否是目标文件类型
                    if ext.lower() in TARGET_EXTENSIONS:
                        self._scan_file(full_path)
                        
        except PermissionError:
            # 如果没有权限访问某个目录，跳过它
            pass
    
    def _scan_file(self, file_path):
        """
        扫描单个文件中的API密钥和供应链攻击特征
        
        参数:
            file_path: 要扫描的文件路径
        """
        # 更新扫描计数
        self.scanned_files_count += 1
        
        # 获取文件名和扩展名
        file_name = os.path.basename(file_path)
        _, ext = os.path.splitext(file_name)
        
        # 检查是否是可疑的 .pth 文件
        if ext.lower() == '.pth':
            self._scan_pth_file(file_path, file_name)
            return
        
        try:
            # 读取文件内容
            # 使用 utf-8 编码，ignore 参数可以跳过无法解码的字符
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # 用于供应链攻击检测的变量
            has_env_access = False
            has_network_send = False
            suspicious_network_target = None
            env_access_line = None
            network_send_line = None
            
            # 逐行扫描
            for line_num, line in enumerate(lines, start=1):
                # 在当前行中搜索API密钥
                matches = API_KEY_PATTERN.findall(line)
                
                # 如果找到了匹配的密钥
                for match in matches:
                    # match 是一个元组，包含4个元素，对应4个分组
                    # 我们需要找到非空的那个分组
                    key = None
                    for group in match:
                        if group:
                            key = group
                            break
                    
                    if key:
                        # 记录这个风险
                        self.found_risks.append({
                            'file': file_path,
                            'line': line_num,
                            'key': key
                        })
                
                # 供应链攻击特征检测
                if ext.lower() == '.py':
                    # 检查环境变量访问
                    if re.search(r'os\.environ|os\.getenv', line, re.IGNORECASE):
                        has_env_access = True
                        env_access_line = line_num
                    
                    # 检查网络外发
                    if re.search(r'requests\.post|requests\.get|urllib\.request|http\.client|socket\.connect', line, re.IGNORECASE):
                        has_network_send = True
                        network_send_line = line_num
                    
                    # 检查可疑的网络目标
                    suspicious_match = SUSPICIOUS_NETWORK_PATTERN.search(line)
                    if suspicious_match:
                        suspicious_network_target = suspicious_match.group()
            
            # 如果同时存在环境变量访问和网络外发，标记为供应链攻击风险
            if has_env_access and has_network_send:
                self.supply_chain_risks.append({
                    'file': file_path,
                    'env_line': env_access_line,
                    'network_line': network_send_line,
                    'target': suspicious_network_target
                })
                    
        except Exception:
            # 如果读取文件失败，跳过这个文件
            pass
    
    def _scan_pth_file(self, file_path, file_name):
        """
        扫描 .pth 文件中的供应链攻击特征
        
        .pth 文件是 Python 的路径配置文件，可以被自动执行
        供应链攻击经常利用这一点来注入恶意代码
        
        参数:
            file_path: .pth 文件的完整路径
            file_name: .pth 文件的文件名
        """
        # 检查是否是可疑的 .pth 文件名
        if file_name.lower() in SUSPICIOUS_PTH_FILES:
            self.supply_chain_risks.append({
                'file': file_path,
                'type': 'suspicious_pth',
                'detail': f'发现可疑的 .pth 文件: {file_name}'
            })
        
        # 检查是否在 site-packages 目录中（更危险）
        if 'site-packages' in file_path.lower():
            self.supply_chain_risks.append({
                'file': file_path,
                'type': 'site_packages_pth',
                'detail': f'发现 site-packages 目录中的 .pth 文件: {file_name}'
            })
        
        try:
            # 读取 .pth 文件内容
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # 检查是否包含可疑的导入或执行代码
            if re.search(r'import\s+os|exec\(|eval\(|__import__', content, re.IGNORECASE):
                self.supply_chain_risks.append({
                    'file': file_path,
                    'type': 'malicious_pth_content',
                    'detail': f'.pth 文件包含可疑的代码执行特征'
                })
                
        except Exception:
            # 如果读取文件失败，跳过
            pass
    
    def _mask_key(self, key):
        """
        对API密钥进行脱敏处理
        
        脱敏的目的：
        - 在报告中显示时，不暴露完整的密钥
        - 保留前几位和后几位，方便开发者识别是哪个密钥
        
        参数:
            key: 原始API密钥
            
        返回:
            脱敏后的密钥字符串，格式如: sk-abc...xyz
        """
        if len(key) <= 8:
            # 如果密钥太短，只显示前3位
            return key[:3] + '...'
        else:
            # 显示前6位和后3位
            return key[:6] + '...' + key[-3:]
    
    def _identify_platform(self, key):
        """
        识别密钥属于哪个平台
        
        参数:
            key: API密钥
            
        返回:
            平台信息字典，如果无法识别则返回 None
        """
        key_lower = key.lower()
        
        # 按优先级检查密钥前缀
        if key_lower.startswith('sk-proj-'):
            return PLATFORM_SIGNATURES.get('sk-proj-')
        elif key_lower.startswith('gsk_'):
            return PLATFORM_SIGNATURES.get('gsk_')
        elif key_lower.startswith('xai-'):
            return PLATFORM_SIGNATURES.get('xai-')
        elif key_lower.startswith('sk-'):
            return PLATFORM_SIGNATURES.get('sk-')
        
        return None
    
    def _generate_report(self):
        """
        生成可视化安全报告（保姆级行动指南版本）
        
        报告特色：
        1. 使用 Emoji 排版，禁用星号
        2. 提供可直接复制执行的命令
        3. 提供平台直达链接
        4. 支持一键修复模式
        """
        print()
        print("=" * 70)
        print("  📊 安全扫描报告")
        print("=" * 70)
        
        # ====================================================================
        # 第一部分：扫描进度
        # ====================================================================
        print()
        print("【 扫描进度 】")
        print(f"  📂 已扫描文件数: {self.scanned_files_count}")
        print()
        
        # ====================================================================
        # 第二部分：发现风险（危险区域）
        # ====================================================================
        print("【🚨 危险】")
        
        has_critical_issues = False
        
        # 检查是否有密钥泄露
        if self.found_risks:
            has_critical_issues = True
            print("【 ⚠️ 敏感信息 】")
            print(f"  🆘 发现 {len(self.found_risks)} 处 API 密钥泄露！")
            print(f"  ⚠️  您的密钥可能已经被盗用，请立即处理！")
            print()
            
            # 识别涉及的平台
            platforms_found = set()
            
            # 列出每一个风险
            for i, risk in enumerate(self.found_risks, start=1):
                rel_path = os.path.relpath(risk['file'], self.target_dir)
                masked_key = self._mask_key(risk['key'])
                
                # 识别平台
                platform_info = self._identify_platform(risk['key'])
                if platform_info:
                    platforms_found.add(platform_info['name'])
                
                print(f"  💀 风险 #{i}")
                print(f"     📄 文件: {rel_path}")
                print(f"     📍 第 {risk['line']} 行")
                print(f"     🔑 密钥: {masked_key}")
                print()
        
        # 检查供应链攻击风险
        if self.supply_chain_risks:
            has_critical_issues = True
            print("【 ☣️ 恶意组件 】")
            print(f"  ☣️  检测到 {len(self.supply_chain_risks)} 处供应链攻击风险！")
            print(f"  🚨 检测到疑似针对 AI 基础设施的供应链攻击特征，请立即物理隔离该开发环境！")
            print()
            
            # 列出每一个供应链攻击风险
            for i, risk in enumerate(self.supply_chain_risks, start=1):
                rel_path = os.path.relpath(risk['file'], self.target_dir)
                
                print(f"  ☣️  供应链风险 #{i}")
                print(f"     📄 文件: {rel_path}")
                
                # 根据风险类型显示不同的信息
                if 'type' in risk:
                    if risk['type'] == 'suspicious_pth':
                        print(f"     🔍 风险类型: 可疑的 .pth 文件")
                        print(f"     💀 细节: {risk.get('detail', '未知')}")
                    elif risk['type'] == 'site_packages_pth':
                        print(f"     🔍 风险类型: site-packages 中的 .pth 文件")
                        print(f"     💀 细节: {risk.get('detail', '未知')}")
                    elif risk['type'] == 'malicious_pth_content':
                        print(f"     🔍 风险类型: .pth 文件包含恶意代码")
                        print(f"     💀 细节: {risk.get('detail', '未知')}")
                else:
                    print(f"     🔍 风险类型: 环境变量窃取 + 网络外发组合")
                    print(f"     💀 环境变量访问: 第 {risk.get('env_line', '未知')} 行")
                    print(f"     💀 网络外发: 第 {risk.get('network_line', '未知')} 行")
                    if risk.get('target'):
                        print(f"     💀 可疑目标: {risk['target']}")
                
                print()
        
        # 检查工程红线问题
        gitignore_issues = []
        if not self.gitignore_exists:
            has_critical_issues = True
            gitignore_issues.append("missing")
            print("  🆘 项目缺少 .gitignore 文件！")
            print("     ⚠️  如果您使用 Git，所有文件都会被上传，包括密码！")
            print()
        elif not self.env_in_gitignore:
            has_critical_issues = True
            gitignore_issues.append("no_env")
            print("  🆘 .gitignore 没有屏蔽 .env 文件！")
            print("     ⚠️  如果您使用 Git，.env 中的密码会被上传！")
            print()
        
        if not has_critical_issues:
            print("  ✅ 未发现安全风险，项目状态良好")
            print()
        
        # ====================================================================
        # 第三部分：救命药方（保姆级修复指南）
        # ====================================================================
        print("【🛠️ 救命药方】")
        print()
        
        # 如果有 .gitignore 问题，提供一键修复命令
        if gitignore_issues:
            print("  📋 步骤 1: 修复 .gitignore 文件")
            print("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            print()
            
            if "missing" in gitignore_issues:
                print("  👉 复制下面这行字，粘贴到你的 VS Code 终端按回车即可修复：")
                print()
                print(f'     echo .env > .gitignore')
                print()
                print("  📝 这行命令会：")
                print("     - 创建一个名为 .gitignore 的文件")
                print("     - 在文件中写入 .env")
                print("     - 告诉 Git 忽略这个危险的文件")
                print()
            
            elif "no_env" in gitignore_issues:
                print("  👉 复制下面这行字，粘贴到你的 VS Code 终端按回车即可修复：")
                print()
                print(f'     echo .env >> .gitignore')
                print()
                print("  📝 这行命令会：")
                print("     - 在 .gitignore 文件末尾追加 .env")
                print("     - 告诉 Git 忽略这个危险的文件")
                print()
        
        # 如果有密钥泄露，提供修复指南
        if self.found_risks:
            print("  📋 步骤 2: 处理泄露的密钥")
            print("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            print()
            print("  ⚠️  重要：以下文件中的密钥需要立即处理：")
            print()
            
            # 列出所有包含风险的文件（去重）
            risk_files = set()
            for risk in self.found_risks:
                rel_path = os.path.relpath(risk['file'], self.target_dir)
                risk_files.add(rel_path)
            
            for f in risk_files:
                print(f"     - {f}")
            
            print()
            print("  👉 请立即执行以下操作：")
            print("     1. 点击下方链接进入平台")
            print("     2. 找到报告中显示的密钥（看前几位就能对上）")
            print("     3. 点击「删除」或「Revoke」按钮")
            print("     4. 重新生成一个新的密钥")
            print()
        
        # ====================================================================
        # 第四部分：传送门（平台直达链接）
        # ====================================================================
        if self.found_risks:
           print("【🔗 救命传送门：一键直达密钥管理】")
           print("  如果发现密钥泄露，请立即点击对应链接进入后台撤销（Revoke）！")
           print()

        print("  🌍 全球主流平台：")
        print("  - OpenAI (GPT): https://platform.openai.com/api-keys")
        print("  - Anthropic (Claude): https://console.anthropic.com/settings/keys")
        print("  - Google (Gemini): https://aistudio.google.com/app/apikey")
        print("  - Groq (极速推理): https://console.groq.com/keys")
        print("  - Grok (xAI): https://console.x.ai/")
        print("  - Mistral AI: https://console.mistral.ai/api-keys/")
        print()

        print("  🇨🇳 国产顶流平台：")
        print("  - DeepSeek (深度求索): https://platform.deepseek.com/api_keys")
        print("  - Xiaomi MiMo (小米): https://platform.xiaomimimo.com/")
        print("  - Moonshot (Kimi): https://platform.moonshot.cn/console/api-keys")
        print("  - Zhipu AI (智谱清言): https://open.bigmodel.cn/usercenter/apikeys")
        print("  - 通义千问 (阿里云): https://dashscope.console.aliyun.com/apiKey")
        print()

        print("  💡 智渔哨兵建议：如果不确定是哪家的 Key，请看一眼报错信息里的域名，或者干脆把上面你用过的平台全检查一遍！安全第一！")



        # ====================================================================
        # 第五部分：一键修复模式
        # ====================================================================
        if gitignore_issues:
            print("【🔧 一键修复模式】")
            print()
            print("  是否需要哨兵自动为您创建 .gitignore 并屏蔽风险文件？")
            print("  👉 输入 Y 即可一键修复")
            print()
            
            # 获取用户输入
            try:
                user_input = input("  请输入您的选择 (Y/N): ").strip().upper()
                print()
                
                if user_input == 'Y':
                    self._auto_fix_gitignore()
                else:
                    print("  ✅ 好的，您可以稍后手动修复")
                    print()
            except (EOFError, KeyboardInterrupt):
                # 非交互模式下跳过
                print("  ℹ️  非交互模式，跳过自动修复")
                print("  💡 提示: 您可以手动运行上面的命令来修复")
                print()
        
        # ====================================================================
        # 报告结尾
        # ====================================================================
        print("=" * 70)
        print("  🛡️  KeySentry 扫描完成")
        print()
        if has_critical_issues:
            print("  ⚠️  警告：发现安全风险，请按照上述步骤立即修复！")
        else:
            print("  ✅ 恭喜！您的项目目前是安全的")
        print("=" * 70)
    
    def _auto_fix_gitignore(self):
        """
        一键修复 .gitignore 文件
        
        这个方法会自动：
        1. 创建或更新 .gitignore 文件（追加模式，不覆盖原有配置）
        2. 确保 .env 被屏蔽
        3. 动态检测 .venv 并给出提示
        """
        gitignore_path = os.path.join(self.target_dir, '.gitignore')
        
        try:
            # .gitignore 的安全堡垒配置内容
            safe_config = """# ============================================================
# 🛡️ KeySentry 自动生成的安全堡垒配置
# 作用：防止敏感密钥、冗余缓存、私人配置上传至云端
# ============================================================

# --- 核心安全区（必须屏蔽！） ---
.env
.env.*
*.env
*.key
*.pem
*.p12
*.pfx
# 屏蔽常见的配置文件（防止有人把 Key 直接写在里面）
config.json
secrets.json
auth.json

# --- 虚拟环境区（防止仓库爆炸） ---
# 如果不屏蔽这个，你的 GitHub 仓库会瞬间塞满几百MB的废品
.venv/
venv/
ENV/
env/
bin/
lib/
# 屏蔽 Python 运行产生的"头皮屑"
__pycache__/
*.py[cod]
*$py.class

# --- 编辑器私人配置区 ---
# 防止你的 VS Code 本地历史记录、调试配置被传上去
.vscode/
.idea/
.DS_Store
Thumbs.db

# --- 临时文件与日志 ---
*.log
tmp/
temp/
"""
            
            # 动态检测 .venv 文件夹
            venv_path = os.path.join(self.target_dir, '.venv')
            has_venv = os.path.exists(venv_path) and os.path.isdir(venv_path)
            
            # 使用追加模式（Append）添加内容，不覆盖用户原有配置
            if os.path.exists(gitignore_path):
                # 文件已存在，用追加模式
                with open(gitignore_path, 'a', encoding='utf-8') as f:
                    f.write('\n' + safe_config)
                
                print("  ✅ 已追加安全配置到 .gitignore 文件")
                print("  📝 使用追加模式，保留了您原有的配置")
            else:
                # 创建新文件
                with open(gitignore_path, 'w', encoding='utf-8') as f:
                    f.write(safe_config)
                
                print("  ✅ 已创建 .gitignore 文件")
                print("  📝 已添加完整的安全屏蔽规则")
            
            # 如果检测到 .venv，给出提示
            if has_venv:
                print()
                print("  🎯 检测到您有虚拟环境，哨兵已自动为您屏蔽，防止仓库臃肿。")
            
            print()
            print("  🎉 修复完成！现在可以安全地使用 Git 了")
            print()
            
        except Exception as e:
            print(f"  ❌ 自动修复失败: {e}")
            print("  💡 请尝试手动运行上方的命令来修复")
            print()


# ============================================================================ 
# 第三部分：供应链攻击检测规则
# 针对 LiteLLM 等 AI 基础设施供应链漏洞的检测
# ============================================================================

# 可疑的 .pth 文件名（供应链攻击常见载体）
SUSPICIOUS_PTH_FILES = {
    'litellm_init.pth',   # LiteLLM 相关的可疑 .pth 文件
}

# 供应链攻击特征：环境变量窃取 + 网络外发组合
SUPPLY_CHAIN_ATTACK_PATTERN = re.compile(
    r'os\.environ|'                           # 访问环境变量
    r'os\.getenv|'                            # 获取环境变量
    r'requests\.post|'                        # 网络外发 POST
    r'requests\.get|'                         # 网络外发 GET
    r'urllib\.request|'                       # URL 请求
    r'http\.client|'                          # HTTP 客户端
    r'socket\.connect',                       # Socket 连接
    re.IGNORECASE
)

# 危险的网络外发目标模式（不明 IP 或可疑域名）
SUSPICIOUS_NETWORK_PATTERN = re.compile(
    r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # 直接 IP 地址
    r'https?://[a-z0-9.-]+\.tk/|'                      # .tk 域名
    r'https?://[a-z0-9.-]+\.ml/|'                      # .ml 域名
    r'https?://[a-z0-9.-]+\.ga/|'                      # .ga 域名
    r'https?://[a-z0-9.-]+\.cf/|'                      # .cf 域名
    r'https?://[a-z0-9.-]+\.gq/|'                      # .gq 域名
    r'pastebin\.com|'                                  # Pastebin
    r'telegram\.org|'                                  # Telegram
    r'discord\.com/api/webhooks',                      # Discord Webhook
    re.IGNORECASE
)


# ============================================================================ 
# 第四部分：主程序入口
# ============================================================================

def main():
    """
    主函数 - 程序的入口点
    
    负责：
    1. 解析命令行参数
    2. 创建扫描器实例
    3. 执行扫描
    """
    # 获取扫描目标目录
    # 如果命令行提供了参数，使用该参数作为目标目录
    # 否则使用当前目录 '.'
    if len(sys.argv) > 1:
        target_dir = sys.argv[1]
    else:
        target_dir = '.'
    
    # 检查目标目录是否存在
    if not os.path.exists(target_dir):
        print(f"❌ 错误: 目录 '{target_dir}' 不存在!")
        sys.exit(1)
    
    # 检查是否是目录
    if not os.path.isdir(target_dir):
        print(f"❌ 错误: '{target_dir}' 不是一个目录!")
        sys.exit(1)
    
    # 创建扫描器并执行扫描
    scanner = SentryScanner(target_dir)
    scanner.scan()


# ============================================================================
# 程序入口
# 当直接运行这个文件时，执行 main() 函数
# 如果这个文件被其他程序导入，则不执行 main()
# ============================================================================
if __name__ == '__main__':
    main()