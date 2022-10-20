from flask import (Flask,session, flash, jsonify, redirect, render_template, request,
                   url_for, send_from_directory, send_file, make_response, Response, render_template_string, abort)

from pkg_imp import app

from controllers netmeds

from werkzeug.security import safe_join
import os

@app.route('/assets/<p1>/<f1>', methods=['GET'])
def asset_share(p1, f1):
    print(p1, f1)
    return send_from_directory(f"assets/{p1}", f"{f1}")


@app.route('/assets/theme-new/<f1>/<f>')
def asset_them_new_f1(f1, f):
    return send_from_directory(f"assets/theme-new/{f1}", f"{f}")

@app.route('/assets/theme-new/<f1>/<f2>/<f>')
def asset_them_new_f1_f2(f1, f2, f):
    return send_from_directory(f"assets/theme-new/{f1}/{f2}", f"{f}")

@app.route('/assets/theme-new/<f1>/<f2>/<f3>/<f>')
def asset_them_new_f1_f2_f3(f1, f2, f3, f):
    return send_from_directory(f"assets/theme-new/{f1}/{f2}/{f3}", f"{f}")

if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0',port=5000)
    
