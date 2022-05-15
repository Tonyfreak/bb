from flask import Flask, render_template, send_file, request, redirect, url_for
import os
import base64
import subprocess

app = Flask(__name__)

#########################################################################

@app.route("/home")
def home():
    return render_template("index.html")

#########################################################################

@app.route("/adder", methods=["GET", "POST"])
def adder():
 if request.method == "POST":
  url = request.form.get('url')
  #DATABASE_URL = os.environ['DATABASE_URL']
   
  subprocess.call(['bash','bas.sh',url])
  return render_template("index.html", info="Added to queue !")


#########################################################################

if __name__ == "__main__":
  app.run(port=8002)
  #app.run(debug=True) 
