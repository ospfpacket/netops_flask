from flask import Flask, render_template, url_for, request, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from netmiko import ConnectHandler
import json
import requests
import shutil
import os


#App & Config, DB, and Encryption
app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'Secret Key'           #adjust for your context

#Login Manager Stuff
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


@app.route("/", methods=["GET"])
@login_required
def home():
    """
    Main web page, contains info about the scripts herein
    """
    return render_template("home.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('home'))

    return render_template('login.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route("/ise", methods=["GET"])
@login_required
def ise():
    """
    This page contains scripts for interacting with ISE
    """
    return render_template("ise.html")


@app.route("/dnac", methods=["GET"])
@login_required
def dnac():
    """
    This page contains scripts for interacting with DNAC
    """
    return render_template("dnac.html")


@app.route("/ise_group", methods=['POST'])
def ise_group():
    mac_addr = request.form["mac_addr"]
    mac_addr = mac_addr.split('\r\n')

    status = ""

    group_name = request.form['Endpoint Group']

    if group_name == 'ISE Group 1':           #adjust for your context
        group_id = 'group-id'           #adjust for your context
    if group_name == 'ISE Group 2':           #adjust for your context
        group_id = 'group-id'           #adjust for your context
    if group_name == 'ISE Group 3':           #adjust for your context
        group_id = 'group-id'           #adjust for your context
    if group_name == 'ISE Group 4':           #adjust for your context
        group_id = 'group-id'           #adjust for your context

    for mac in mac_addr:
        ep_id = ""

        url = "https://ISE URL and Port Here/ers/config/endpoint/name/"+ mac           #adjust for your context

        payload={}
        
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': 'Base64 Hashed Username and Password Here'           #adjust for your context
        }

        response = requests.request("GET", url, headers=headers, data=payload, verify = False)     #SSL Verification is turned off. Should be enabled in production.

        #print(response.status_code)     #This is for debugging in the console

        if response.status_code == 200:
            #This parses the mac address endpoint id and sets the variable ep_id
            response = json.loads(response.text)
            response = response.get('ERSEndPoint')
            ep_id = (response['id'])
        elif response.status_code == 404:
            status = status + mac + " was not found in ISE. Please verify the MAC address and try again.\r\n"
        elif response.status_code == 500:
            status = status + mac + " is an invalid MAC. Please verify the MAC address and try again.\r\n"
        else:
            status = status + mac + " threw an unhandled exception. Please contact your system administrator.\r\n"

        if ep_id != "":
            url = "https://ISE URL and Port Here/ers/config/endpoint/"+ ep_id           #adjust for your context

            payload = json.dumps({
                "ERSEndPoint": {
                "groupId": group_id,
                "staticGroupAssignment": True
            }
            })

            response = requests.request("PUT", url, headers=headers, data=payload, verify = False)
            
            #print(response.status_code)     #This is for debugging in the console

            if response.status_code == 200:
                status = status + mac + " has been added to " + group_name + ".\r\n"
            else:
                status = status + mac + " threw an unhandled exception. Please contact your system administrator.\r\n"

    return render_template('ise.html', status=status)

@app.route("/ise_create", methods=['POST'])
def ise_create():
    mac_addr = request.form["mac_addr"]
    mac_addr = mac_addr.split('\r\n')

    status = ""

    for mac in mac_addr:

        url = "https://ISE URL and Port Here/ers/config/endpoint"           #adjust for your context

        payload = json.dumps({
            "ERSEndPoint": {
            "name": mac,
            "mac": mac
            }
        })
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': 'Base64 Hashed Username and Password'           #adjust for your context
        }

        response = requests.request("POST", url, headers=headers, data=payload, verify = False)

        #print(response.status_code)     #This is for debugging in the console
        
        if response.status_code == 201:
            status = status + mac + " has been added to the ISE database.\r\n"
        elif response.status_code == 500:
            status = status + "Unable to create the endpoint. " + mac + " already exists in the ISE database.\r\n"
        else:
            status = status + mac + " threw an unhandled exception. Please contact your system administrator.\r\n"
            
        
    return render_template('ise.html', status=status)

@app.route("/ise_delete", methods=['POST'])
def ise_delete():
    mac_addr = request.form["mac_addr"]
    mac_addr = mac_addr.split('\r\n')

    status = ""

    for mac in mac_addr:
        ep_id = ""
        url = "https://ISE URL and Port Here/ers/config/endpoint/name/" + mac           #adjust for your context

        payload={}
        
        headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': 'Base64 Hashed Username and Password'           #adjust for your context
        }

        response = requests.request("GET", url, headers=headers, data=payload, verify = False)     #SSL Verification is turned off. Should be enabled in production.
        
        #print(response.status_code)     #This is for debugging in the console

        if response.status_code == 200:
            response = json.loads(response.text)
            response = response.get('ERSEndPoint')
            ep_id = (response['id'])
        elif response.status_code == 404:
            status = status + mac + " was not found in ISE. Please verify the MAC address and try again.\r\n"
        else:
            status = status + mac + " threw an unhandled exception. Please contact your system administrator.\r\n"
        
        if ep_id != "":
            url = "https://ISE UR and Port Here/ers/config/endpoint/" + ep_id           #adjust for your context

            response = requests.request("DELETE", url, headers=headers, data=payload, verify = False)     #SSL Verification is turned off. Should be enabled in production.

            #print(response.status_code)     #This is for debugging in the console

            if response.status_code == 204:
                status = status + "MAC Address " + mac + " has been removed from ISE!\r\n"
            elif response.status_code == 404:
                status = "Endpoint was not found in ISE. Please verify the MAC address and try again.\r\n"
            else:
                status = "Unhandled Exception. Please contact your system administrator.\r\n"
            
    return render_template('ise.html', status=status)

@app.route("/dnac_ip", methods=['POST'])
def dnac_ip():
    url = "https://DNAC URL Here/api/system/v1/auth/token"           #adjust for your context

    payload = ""
    headers = {
        'Authorization': 'Base64 Hashed Username and Password'           #adjust for your context
    }

    response = requests.request("POST", url, headers=headers, data=payload, verify = False)
    #print(response.status_code)     #Enable when troubleshooting in console
    response = json.loads(response.text)
    token = (response['Token'])
    
    ip_addr = request.form["ip_addr"]

    url = "https://DNAC URL and Port Here/api/v1/host?hostIp=" + ip_addr           #adjust for your context

    payload={}
    headers = {
    'x-auth-token': token
    }

    response = requests.request("GET", url, headers=headers, data=payload, verify = False)
    #print(response.status_code)     #Enable when troubleshooting in console
    response = json.loads(response.text)     #Response is a List of Dict
    response = response.get('response')      #Pull in the KVPair you want to work with
    if len(response) > 0:
        response = response[0]               #Convert to a straight dictionary for ease of data extraction
    else:
        status = "Host not found in DNAC."
        return render_template('dnac.html', status=status)

    if response['hostType'] == 'Wired':

        hostIp = response['hostIp']
        hostMac = response['hostMac']
        networkDevice = response['connectedNetworkDeviceName']
        interface = response['connectedInterfaceName']
        status = ("IP Address: " + hostIp + "\n"
                "MAC Address: " + hostMac + "\n"
                "Switch: " + networkDevice + "\n"
                "Interface: " + interface
        )
        return render_template('dnac.html', status=status)

    elif response['hostType'] == 'Wireless':
        hostIp = response['hostIp']
        hostMac = response['hostMac']
        apName = response['connectedAPName']
        wlanName = response['wlanNetworkName']
        status = ("IP Address: " + hostIp + "\n"
                "MAC Address: " + hostMac + "\n"
                "Access Point: " + apName + "\n"
                "SSID: " + wlanName
        )
        return render_template('dnac.html', status=status)

@app.route("/dnac_mac", methods=['POST'])
def dnac_mac():
    url = "https://DNAC URL Here/api/system/v1/auth/token"           #adjust for your context

    payload = ""
    headers = {
        'Authorization': 'Base64 Hashed Username and Password'           #adjust for your context
    }

    response = requests.request("POST", url, headers=headers, data=payload, verify = False)
    #print(response.status_code)     #Enable when troubleshooting in console
    response = json.loads(response.text)
    
    token = (response['Token'])
    
    mac_addr = request.form['mac_addr']

    url = "https://DNA Center URL and Port Here/dna/intent/api/v1/client-detail?macAddress=" + mac_addr           #adjust for your context

    payload={}
    headers = {
        'x-auth-token': token,
        '__runsync': 'True'
    }

    response = requests.request("GET", url, headers=headers, data=payload, verify = False)
    #print(response.status_code)     #Enable when troubleshooting in console
    response = json.loads(response.text)
    detail = response.get('detail')
    if len(detail) == 0:
        status = "Host not found in DNAC."
        return render_template('dnac.html', status=status)
    hostName = str(detail['hostName'])
    hostMac = str(detail['hostMac'])
    vlanId = str(detail['vlanId'])
    hostIpV4 = str(detail['hostIpV4'])
    ssid = str(detail['ssid'])
    port = str(detail['port'])
    connectedAP = str(detail['clientConnection'])
    healthScore = detail.get('healthScore')
    overallHealth = (str(healthScore[0]['score']))
    
    status = ('Hostname: ' + hostName + "\n"
            'IP Address: ' + hostIpV4 + "\n"
            'MAC Address: ' + hostMac + "\n"
            'VLAN: ' + vlanId + "\n"
            'Connected AP/Switch: ' + connectedAP + "\n"
            'SSID: ' + ssid + "\n"
            'Switchport: ' + port + "\n"
            'Overall Health: ' + overallHealth
    )

    return render_template('dnac.html', status=status)

@app.route("/general", methods=['GET'])
@login_required
def general():
    return render_template("general.html")

@app.route('/config_backup', methods=['POST'])
def config_backup():
    username = "username"           #adjust for your context
    password = "password"           #adjust for your context
    status = ""

    hostname = request.form['hostname']

    path = "./temp_files/" + hostname + ".txt"

    device = {
        'device_type': 'cisco_ios',
        'host':   hostname,
        'username': username,
        'password': password,
    }

    net_connect = ConnectHandler(**device)
    output = net_connect.send_command('terminal length 0')
    output = net_connect.send_command('show run')
    with open(path, 'w') as f:
        f.write(output)
        f.close

    source = path
    destination = r"destionation_path"           #adjust for your context
    shutil.copy(source, destination)
    os.remove(source)

    status = "Configuration for " + hostname + " has been stored on the P: drive."

    return render_template('general.html', status=status)

@app.route('/inet_stats', methods=['POST'])
def inet_stats():
    status = ""
    username = "username"           #adjust for your context
    password = "password"           #adjust for your context

    Router1 = {
        'device_type': 'cisco_ios',
        'host':   'ip_address',           #adjust for your context
        'username': username,
        'password': password,
    }

    Router2 = {
        'device_type': 'cisco_ios',
        'host':   'ip_address',           #adjust for your context
        'username': username,
        'password': password,
    }

    net_connect = ConnectHandler(**Router1)
    output1 = net_connect.send_command('show int ____ hum | inc Description|reliability|rate|errors') + "\r\n" + "\r\n"           #adjust for your context
    output1 = output1 + net_connect.send_command('show int ten ____ hum | inc Description|reliability|rate|errors') + "\r\n" + "\r\n"           #adjust for your context

    net_connect = ConnectHandler(**Router2)
    output1 = output1 + net_connect.send_command('show int ten ____ hum | inc Description|reliability|rate|errors')           #adjust for your context
    
    status = output1

    return render_template('general.html', status=status)

@app.route("/bgp_neigh", methods=['POST'])
def bgp_neigh():
    username = "enter username here"           #adjust for your context
    password = "enter password here"           #adjust for your context
    status = ""
    output =  ""

    rtr = ['device 1',           #adjust for your context
           'device 2',           #adjust for your context
           'device 3',           #adjust for your context
           'device n',           #adjust for your context
          ]

    for device in rtr:
        device = {
            'device_type': 'cisco_ios',
            'host':   device,
            'username': username,
            'password': password,
        }

        net_connect = ConnectHandler(**device)
        output = output + net_connect.send_command('show ip bgp summ | inc localAS|ISP1AS|ISP2AS') + "\r\n" + "\r\n"           #adjust for your context
        status = output
    
    return render_template('general.html', status=status)

if __name__ == "__main__":
    app.run(debug='True')