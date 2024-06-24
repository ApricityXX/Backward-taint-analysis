import shutil

from flask import Flask, request, jsonify, send_from_directory, render_template
import subprocess
import os

from scipy.linalg._interpolative import idd_frm

app = Flask(__name__, static_url_path='', static_folder='static')
UPLOAD_FOLDER = 'uploads'

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


def allowed_file(filename):
    return True


@app.route('/', methods=['GET'])
def index():
    return render_template("index.html")


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return render_template("index.html", tips="No file part")
    file = request.files['file']
    if file.filename == '':
        return render_template("index.html", tips="No selected file")
    if file:  # 现在这个检查总是为True，因为我们允许所有文件类型
        filename = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filename)
        os.chmod(filename, 0o755)  # Make the file executable
        try:
            subprocess.run(['./rdCode', '-i', filename], check=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            if os.path.exists(f"./results/{file.filename}_system.png"):
                shutil.copyfile(f"./results/{file.filename}_system.png", f"static/{file.filename}_system.png")
                return render_template("index.html", tips="success", user_image=f"{file.filename}_system.png")
            else:
                return render_template("index.html", tips="not exist")
        except subprocess.CalledProcessError as e:
            error_output = e.stderr.decode().strip()
            return render_template("index.html", tips=error_output)
    return render_template("index.html", tips="An unexpected error occurred")


if __name__ == '__main__':
    os.chmod('./rdCode', 0o755)
    app.run(debug=True, host='0.0.0.0')
