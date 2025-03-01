from flask import Flask, render_template

app = Flask(__name__) 

@app.route('/') 
def home():
    return render_template('index.html')

@app.route('/about') 
def about():
    return render_template('about.html') 

@app.route('/admin') 
def admin():
    return render_template('admin.html') 

@app.route('/confirmation') 
def confirmation():
    return render_template('confirmation.html') 

@app.route('/history') 
def history():
    return render_template('history.html') 

@app.route('/login') 
def login():
    return render_template('login.html') 

@app.route('/portfolio') 
def portfolio():
    return render_template('portfolio.html') 

@app.route('/profile') 
def profile():
    return render_template('profile.html') 

@app.route('/signup') 
def signup():
    return render_template('signup.html') 

@app.route('/stocks')  # Changed from 'stock' to 'stocks' to match your file
def stocks():
    return render_template('stocks.html') 

if __name__ == '__main__':    
    app.run(debug=True)
