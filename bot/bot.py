import logging
import re
import paramiko
import shlex
import psycopg2
import os
import subprocess
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, ConversationHandler, CallbackContext

load_dotenv()

TOKEN = os.getenv('TOKEN')

logging.basicConfig(
    filename='logfile.txt', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO
)

logger = logging.getLogger(__name__)



hostname = os.getenv('RM_HOST')
port = os.getenv('RM_PORT')
username = os.getenv('RM_USER')
password = os.getenv('RM_PASSWORD')

db_host = os.getenv('DB_HOST')
db_port = os.getenv('DB_PORT')
db_username = os.getenv('DB_USER')
db_password = os.getenv('DB_PASSWORD')
db_database = os.getenv('DB_DATABASE')

def start(update: Update, context):
    global user
    user = update.effective_user
    update.message.reply_text(f'Hello, {user.full_name}!')
    logger.info(f'{user.full_name} started bot')

def helpCommand(update: Update, context):
    update.message.reply_text('Help!')

def get_release(update, context):
    logger.info(f'get release by {user.full_name}')
    args = context.args
    if len(args) != 3:
        update.message.reply_text("Usage: /get_release [host] [username] [password]")
        return
    host, username, password = args
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(host, username=username, password=password)
        stdin, stdout, stderr = ssh_client.exec_command('lsb_release -d')
        release_info = stdout.read().decode()
        ssh_client.close()
        update.message.reply_text(release_info.strip())
    except Exception as e:
        logging.error(f"Error getting release info: {e}")
        update.message.reply_text("Error getting release info")

def get_uname(update, context):
    logger.info(f'get uname by {user.full_name}')
    args = context.args
    if len(args) != 3:
        update.message.reply_text("Usage: /get_uname [host] [username] [password]")
        return
    host, username, password = args
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(host, username=username, password=password)
        stdin, stdout, stderr = ssh_client.exec_command('uname -a')
        uname_info = stdout.read().decode()
        ssh_client.close()
        update.message.reply_text(uname_info.strip())
    except Exception as e:
        logging.error(f"Error getting uname info: {e}")
        update.message.reply_text("Error getting uname info")

def get_uptime(update, context):
    logger.info(f'get uptime by {user.full_name}')
    args = context.args
    if len(args) != 3:
        update.message.reply_text("Usage: /get_uptime [host] [username] [password]")
        return
    host, username, password = args
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(host, username=username, password=password)
        stdin, stdout, stderr = ssh_client.exec_command('uptime')
        uptime_info = stdout.read().decode()
        ssh_client.close()
        update.message.reply_text(uptime_info.strip())
    except Exception as e:
        logging.error(f"Error getting uptime info: {e}")
        update.message.reply_text("Error getting uptime info")


def get_df(update, context):
    logger.info(f'get df by {user.full_name}')
    args = context.args
    if len(args) != 3:
        update.message.reply_text("Usage: /get_df [host] [username] [password]")
        return
    host, username, password = args
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(host, username=username, password=password)
        stdin, stdout, stderr = ssh_client.exec_command('df -h')
        df_info = stdout.read().decode()
        ssh_client.close()
        update.message.reply_text(df_info.strip())
    except Exception as e:
        logging.error(f"Error getting df info: {e}")
        update.message.reply_text(f"Error getting df info")

def get_free(update, context):
    logger.info(f'get free by {user.full_name}')
    args = context.args
    if len(args) != 3:
        update.message.reply_text("Usage: /get_free [host] [username] [password]")
        return
    host, username, password = args
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(host, username=username, password=password)
        stdin, stdout, stderr = ssh_client.exec_command('free -m')
        free_info = stdout.read().decode()
        ssh_client.close()
        update.message.reply_text(free_info.strip())
    except Exception as e:
        logging.error(f"Error getting free info: {e}")
        update.message.reply_text("Error getting free info")

def get_mpstat(update, context):
    logger.info(f'get mpstat by {user.full_name}')
    args = context.args
    if len(args) != 3:
        update.message.reply_text("Usage: /get_mpstat [host] [username] [password]")
        return
    host, username, password = args
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(host, username=username, password=password)
        stdin, stdout, stderr = ssh_client.exec_command('mpstat -A')
        mpstat_info = stdout.read().decode()
        ssh_client.close()
        update.message.reply_text(mpstat_info.strip())
    except Exception as e:
        logging.error(f"Error getting mpstat info: {e}")
        update.message.reply_text("Error getting mpstat info")

def get_w(update, context):
    logger.info(f'get w by {user.full_name}')
    args = context.args
    if len(args) != 3:
        update.message.reply_text("Usage: /get_w [host] [username] [password]")
        return
    host, username, password = args
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(host, username=username, password=password)
        stdin, stdout, stderr = ssh_client.exec_command('w')
        w_info = stdout.read().decode()
        ssh_client.close()
        update.message.reply_text(w_info.strip())
    except Exception as e:
        logging.error(f"Error getting w info: {e}")
        update.message.reply_text("Error getting w info")


def get_auths(update, context):
    logger.info(f'get w by {user.full_name}')
    args = context.args
    if len(args) != 3:
        update.message.reply_text("Usage: /get_auths [host] [username] [password]")
        return
    host, username, password = args
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(host, username=username, password=password)
        stdin, stdout, stderr = ssh_client.exec_command('last -10')
        auths_info = stdout.read().decode()
        ssh_client.close()
        update.message.reply_text(auths_info.strip())
    except Exception as e:
        logging.error(f"Error getting auths info: {e}")
        update.message.reply_text("Error getting auths info")

def get_critical(update, context):
    logger.info(f'get critical info by {user.full_name}')
    args = context.args
    if len(args) != 3:
        update.message.reply_text("Usage: /get_critical [host] [username] [password]")
        return
    host, username, password = args
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(host, username=username, password=password)
        stdin, stdout, stderr = ssh_client.exec_command('journalctl -r -p crit -n 5')
        critical_info = stdout.read().decode()
        ssh_client.close()
        update.message.reply_text(critical_info.strip())
    except Exception as e:
        logging.error(f"Error getting critical info: {e}")
        update.message.reply_text("Error getting critical info")

def get_ps(update, context):
    logger.info(f'get ps by {user.full_name}')
    args = context.args
    if len(args) != 3:
        update.message.reply_text("Usage: /get_ps [host] [username] [password]")
        return
    host, username, password = args
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(host, username=username, password=password)
        stdin, stdout, stderr = ssh_client.exec_command('ps')
        ps_info = stdout.read().decode()
        ssh_client.close()
        update.message.reply_text(ps_info.strip())
    except Exception as e:
        logging.error(f"Error getting ps info: {e}")
        update.message.reply_text("Error getting ps info")

def get_ss(update, context):
    logger.info(f'get ss by {user.full_name}')
    args = context.args
    if len(args) != 3:
        update.message.reply_text("Usage: /get_ss [host] [username] [password]")
        return
    host, username, password = args
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(host, username=username, password=password)
        stdin, stdout, stderr = ssh_client.exec_command('ss -ntlp')
        ss_info = stdout.read().decode()
        ssh_client.close()
        update.message.reply_text(ss_info.strip())
    except Exception as e:
        logging.error(f"Error getting ss info: {e}")
        update.message.reply_text("Error getting ss info")

def get_apt_list(update, context):
    logger.info(f'get apt list by {user.full_name}')
    args = context.args
    if len(args) != 3:
        update.message.reply_text("Usage: /get_apt_list [host] [username] [password]")
        return
    host, username, password = args
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(host, username=username, password=password)
        stdin, stdout, stderr = ssh_client.exec_command('apt list --installed | head -n 20')
        apt_info = stdout.read().decode()
        ssh_client.close()
        update.message.reply_text(apt_info.strip())
    except Exception as e:
        logging.error(f"Error getting apt list info: {e}")
        update.message.reply_text("Error getting apt list info")

def get_services(update, context):
    logger.info(f'get services by {user.full_name}')
    args = context.args
    if len(args) != 3:
        update.message.reply_text("Usage: /get_services [host] [username] [password]")
        return
    host, username, password = args
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(host, username=username, password=password)
        stdin, stdout, stderr = ssh_client.exec_command('service --status-all | head -n 20')
        services_info = stdout.read().decode()
        ssh_client.close()
        update.message.reply_text(services_info.strip())
    except Exception as e:
        logging.error(f"Error getting services info: {e}")
        update.message.reply_text(f"Error getting services info")

def get_apt_show(update, context):
    logger.info(f'get apt show by {user.full_name}')
    args = context.args
    if len(args) != 4:
        update.message.reply_text("Usage: /get_apt_show [host] [username] [password] [package]")
        return
    host, username, password, package = args
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(host, username=username, password=password)
        stdin, stdout, stderr = ssh_client.exec_command(f'apt update | apt show {package}')
        ss_info = stdout.read().decode()
        ssh_client.close()
        update.message.reply_text(ss_info.strip())
    except Exception as e:
        logging.error(f"Error getting apt show info: {e}")
        update.message.reply_text("Error getting apt show info")


def findPhoneNumbersCommand(update: Update, context):
    logger.info(f"find_phone_numbers by {user.full_name}")
    update.message.reply_text('Enter text to find numbers: ')
    return 'findPhoneNumbers'

def findPhoneNumbers(update: Update, context):
    user_input = update.message.text

    phoneNumRegex = re.compile(r"\+?7[ -]?\(?\d{3}\)?[ -]?\d{3}[ -]?\d{2}[ -]?\d{2}|\+?7[ -]?\d{10}|\+?7[ -]?\d{3}[ -]?\d{3}[ -]?\d{4}|8[ -]?\(?\d{3}\)?[ -]?\d{3}[ -]?\d{2}[ -]?\d{2}|8[ -]?\d{10}|8[ -]?\d{3}[ -]?\d{3}[ -]?\d{4}")
    global phoneNumberList
    phoneNumberList = phoneNumRegex.findall(user_input)

    if not phoneNumberList:
        update.message.reply_text('Numbers are not found in the text.')
        return ConversationHandler.END

    phoneNumbers = ''
    for i, phone_tuple in enumerate(phoneNumberList):
        phone = ''.join(phone_tuple)
        phoneNumbers += f'{i+1}. {phone}\n'
        logger.info(f'New phone number {phone} found in text')

    update.message.reply_text(phoneNumbers)

    update.message.reply_text('Do you want to save found phone numbers in the database? Yes/No.')
    return 'savePhoneNumbers'

def savePhoneNumbers(update: Update, context):
    user_input = update.message.text.lower()
    if user_input == 'yes':
        conn = psycopg2.connect(
            dbname=db_database,
            user=db_username,
            password=db_password,
            host=db_host
        )
        cur = conn.cursor()
        for phone_tuple in phoneNumberList:
            phone = ''.join(phone_tuple)
            cur.execute(f"insert into phone_numbers (value) values ('{phone}');")
            logger.info(f'New phone number {phone} was written to database')
        cur.close()
        conn.commit()
        conn.close()

        update.message.reply_text('Phone numbers successfully saved!')
    elif user_input == 'no':
        update.message.reply_text('Nothing will be saved.')
    else:
        update.message.reply_text('Please answer "Yes" or "No".')

    return ConversationHandler.END

def findEmailsCommand(update: Update, context):
    logger.info(f'find_email by {user.full_name}')
    update.message.reply_text('Enter text to find email-addresses: ')
    return 'findEmails'


def findEmails(update: Update, context):
    user_input = update.message.text

    emailRegex = r'\b[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+(?:\.[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+)*' \
                 r'@(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    global emailList
    emailList = re.findall(emailRegex, user_input)

    if not emailList:
        update.message.reply_text('Email-addresses are not found in the promoted text.')
        return

    emails = '\n'.join(emailList)
    update.message.reply_text(emails)
    update.message.reply_text('Do you want to save found email addresses in the database? Yes/No.')
    return 'saveEmails'

def saveEmails(update: Update, context):
    user_input = update.message.text.lower()
    if user_input == 'yes':
        conn = psycopg2.connect(
            dbname=db_database,
            user=db_username,
            password=db_password,
            host=db_host
        )
        cur = conn.cursor()
        for email_tuple in emailList:
            email = ' '.join(email_tuple).replace(" ","")
            cur.execute(f"insert into emails (email) values ('{email}');")
            logger.info(f'New email addres {email} was written to database')
        cur.close()
        conn.commit()
        conn.close()

        update.message.reply_text('Email addresses successfully saved!')
    elif user_input == 'no':
        update.message.reply_text('Nothing will be saved.')
    else:
        update.message.reply_text('Please answer "Yes" or "No".')

    return ConversationHandler.END


def verifyPasswordCommand(update: Update, context):
    update.message.reply_text('Enter the password for checking complexity: ')
    return 'verifyPassword'


def verifyPassword(update: Update, context):
    user_input = update.message.text
    logger.info(f'Password verification by {user.full_name} , password {user_input}')
    passwordRegex = re.compile(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()])[A-Za-z\d!@#$%^&*()]{8,}$')

    if passwordRegex.match(user_input):
        update.message.reply_text('Password is difficult')
    else:
        update.message.reply_text('Password is simple')

    return ConversationHandler.END


def get_logs(update: Update, context):
    logger.info(f"Get logs by {user.full_name}")
    command = "cat /var/log/postgresql/postgresql.log | grep repl | tail -n 15"
    res = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if res.returncode != 0 or res.stderr.decode() != "":
        update.message.reply_text("Error open log file!")
    else:
        update.message.reply_text(res.stdout.decode().strip('\n'))
def get_emails(update: Update, context):
    logger.info(f"Get emails by {user.full_name}")
    conn = psycopg2.connect(
        dbname=db_database,
        user=db_username,
        password=db_password,
        host=db_host
    )
    cur = conn.cursor()
    cur.execute("SELECT email FROM emails")
    emails = cur.fetchall()
    for email in emails:
        update.message.reply_text(email[0])
    cur.close()
    conn.close()

def get_phone_numbers(update: Update, context):
    logger.info(f"Get phone numbers by {user.full_name}")
    conn = psycopg2.connect(
        dbname=db_database,
        user=db_username,
        password=db_password,
        host=db_host
    )
    cur = conn.cursor()
    cur.execute("SELECT value FROM phone_numbers")
    emails = cur.fetchall()
    for email in emails:
        update.message.reply_text(email[0])
    cur.close()
    conn.close()

def echo(update: Update, context):
    update.message.reply_text(update.message.text)


def main():
    updater = Updater(TOKEN, use_context=True)
    dp = updater.dispatcher

    convHandlerFindPhoneNumbers = ConversationHandler(
        entry_points=[CommandHandler('find_phone_number', findPhoneNumbersCommand)],
        states={
            'findPhoneNumbers': [MessageHandler(Filters.text & ~Filters.command, findPhoneNumbers)],
            'savePhoneNumbers': [MessageHandler(Filters.text & ~Filters.command, savePhoneNumbers)]
            },
        fallbacks=[]
    )

    convHandlerFindEmails = ConversationHandler(
        entry_points=[CommandHandler('find_email', findEmailsCommand)],
        states={
            'findEmails': [MessageHandler(Filters.text & ~Filters.command, findEmails)],
            'saveEmails': [MessageHandler(Filters.text & ~Filters.command, saveEmails)]
            },
        fallbacks=[]
    )

    convHandlerVerifyPassword = ConversationHandler(
        entry_points=[CommandHandler('verify_password', verifyPasswordCommand)],
        states={'verifyPassword': [MessageHandler(Filters.text & ~Filters.command, verifyPassword)],},
        fallbacks=[]
    )

    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(CommandHandler("help", helpCommand))
    dp.add_handler(CommandHandler("get_release", get_release, pass_args=True))
    dp.add_handler(CommandHandler("get_uname", get_uname, pass_args=True))
    dp.add_handler(CommandHandler("get_uptime", get_uptime, pass_args=True))
    dp.add_handler(CommandHandler("get_df", get_df, pass_args=True))
    dp.add_handler(CommandHandler("get_free", get_free, pass_args=True))
    dp.add_handler(CommandHandler("get_mpstat", get_mpstat, pass_args=True))
    dp.add_handler(CommandHandler("get_w", get_w, pass_args=True))
    dp.add_handler(CommandHandler("get_auths", get_auths, pass_args=True))
    dp.add_handler(CommandHandler("get_critical", get_critical, pass_args=True))
    dp.add_handler(CommandHandler("get_ps", get_ps, pass_args=True))
    dp.add_handler(CommandHandler("get_ss", get_ss, pass_args=True))
    dp.add_handler(CommandHandler("get_apt_list", get_apt_list, pass_args=True))
    dp.add_handler(CommandHandler("get_apt_show", get_apt_show, pass_args=True))
    dp.add_handler(CommandHandler("get_services", get_services, pass_args=True))
    dp.add_handler(CommandHandler("get_repl_logs", get_logs))
    dp.add_handler(CommandHandler("get_emails", get_emails))
    dp.add_handler(CommandHandler("get_phone_numbers", get_phone_numbers))
    dp.add_handler(convHandlerFindPhoneNumbers)
    dp.add_handler(convHandlerFindEmails)
    dp.add_handler(convHandlerVerifyPassword)

    dp.add_handler(MessageHandler(Filters.text & ~Filters.command, echo))

    updater.start_polling()

    updater.idle()


if __name__ == '__main__':
    main()
