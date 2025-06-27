import os
import subprocess
import tree_sitter_python as tspython
from tree_sitter import Language, Parser
import markdown

# 克隆 GitHub 代码库
def clone_repository(repo_url, local_path):
    if not os.path.exists(local_path):
        subprocess.run(['git', 'clone', repo_url, local_path])
    else:
        print(f"Repository already exists at {local_path}")


# 构建 tree-sitter 语言库
def build_language(language_path, language_name):
    # 生成动态库路径（根据操作系统自动处理扩展名）
    system = os.name
    if system == 'nt':  # Windows
        lib_name = f'{language_name}.dll'
    else:  # Linux/Mac
        lib_name = f'{language_name}.so'

    # 确保指向 grammar.js 文件
    grammar_file = os.path.join(language_path, 'grammar.js')
    # 使用tree-sitter CLI生成解析器
    tree_sitter_path = "D:/devTool/nodejs/node_global/tree-sitter.cmd"
    subprocess.run([
        tree_sitter_path, 'generate',
        grammar_file,
        '--output', lib_name
    ], check=True)
    return Language(tspython.language())
# 解析代码文件
def parse_file(parser, file_path):
    with open(file_path, 'rb') as f:
        code = f.read()
    tree = parser.parse(code)
    root_node = tree.root_node

    # 新增：收集代码信息
    info = []
    for node in root_node.children:
        if node.type == 'function_definition':
            info.append({
                "name": node.child_by_field_name('name').text.decode('utf-8'),
                "type": "Function",
                "description": code[node.start_byte:node.end_byte].decode('utf-8')
            })
        elif node.type == 'class_definition':
            info.append({
                "name": node.child_by_field_name('name').text.decode('utf-8'),
                "type": "Class",
                "description": code[node.start_byte:node.end_byte].decode('utf-8')
            })
    return info


# 生成 Markdown 文档
def generate_markdown_doc(info):
    markdown_content = "# Code Documentation\n\n"
    for item in info:
        markdown_content += f"## {item['name']}\n\n"
        markdown_content += f"**Type**: {item['type']}\n\n"
        markdown_content += f"**Description**: {item['description']}\n\n"
    return markdown_content

# 主函数
def main():
    # GitHub 代码库地址
    # repo_url = 'https://github.com/browser-use/browser-use.git'
    # # 本地保存路径
    local_path = 'E:/code/python_workspace/python-sdk'
    # # 克隆代码库
    # clone_repository(repo_url, local_path)

    # 假设代码库是 Python 代码，使用 Python 解析器
    python_language_path = 'E:/code/python_workspace/tree-sitter-python'  # 需要替换为实际的 Python 解析器路径
    language = build_language(python_language_path, 'python')

    parser = Parser(language=language)

    # 遍历代码库中的所有 Python 文件
    for root, dirs, files in os.walk(local_path):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                parse_file(parser, file_path)

    # 修改：收集所有文件的信息
    all_info = []
    for root, dirs, files in os.walk(local_path):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                all_info.extend(parse_file(parser, file_path))

    # 生成 Markdown 文档
    markdown_doc = generate_markdown_doc(all_info)

    # 保存 Markdown 文档
    with open('mcp/mcp-python-sdk.md', 'w', encoding='utf-8') as f:
        f.write(markdown_doc)

    print("Markdown 文档已生成：mcp-python-sdk.md")

if __name__ == "__main__":
    main()
