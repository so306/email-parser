from __future__ import print_function

import os.path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

import pprint
import base64
import email ###
import re
import flask
import my_parser
import nltk
import heapq
import datetime


# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

senders = {}
emailid_to_subject_date = {} # emailID => subject, date, summary

@my_parser.app.route("/", methods=['GET'])
def test():
    """ does stuff """
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    
    sorted_unread_senders = []
    ids_unread_msgs = []

    try:
        # Call the Gmail API
        service = build('gmail', 'v1', credentials=creds)

        # what is users()
        unread_msgs = service.users().messages().list(userId='me',labelIds=['INBOX', 'UNREAD']).execute()
        pp = pprint.PrettyPrinter(indent=4)
        ids_unread_msgs = [msg['id'] for msg in unread_msgs['messages']] # id vs thread_id
        # pp.pprint(threadids_unread_msgs)

        for email_id in ids_unread_msgs:
            message_list_full = service.users().messages().get(userId='me', id=email_id, format='full').execute()
            payload = message_list_full['payload']

            unread_emails_headers = payload['headers']

            default_date = datetime.datetime(year=datetime.MAXYEAR,month=1, day=31)
            default_date_str = "{:%b %d, %Y}".format(default_date)

            emailid_to_subject_date[email_id] = ["", default_date_str, ""]

            for header in unread_emails_headers:
                if(header['name'] == 'Subject'):
                    emailid_to_subject_date[email_id][0] = header['value']
                if header['name'] == 'From':
                    if header['value'] not in senders:
                        senders[header['value']] = 1
                    else:
                        senders[header['value']] += 1

        sorted_unread_senders = sorted(senders.items(), key=lambda x:x[1], reverse=True)
        # out of _(#100?)__ most recent unread emails, ___

        for email_id in ids_unread_msgs:
            message_list_raw = service.users().messages().get(userId='me', id=email_id, format='raw').execute()
            msg_raw = base64.urlsafe_b64decode(message_list_raw['raw'].encode('utf-8'))
            msg_str = email.message_from_bytes(msg_raw)

            str_msg = msg_str.as_string()
            idx_plain = str_msg.find("Content-Type: text/plain")
            idx_html = str_msg.find("Content-Type: text/html")
            email_content = str_msg[idx_plain:idx_html]
            date = find_email_dates(email_id, email_content)
            if date is not None:
                date_str = "{:%b %d, %Y}".format(date)
                emailid_to_subject_date[email_id][1] = date_str
            emailid_to_subject_date[email_id][2] = process_email(email_content)

        sorted_unread_emails = sorted(emailid_to_subject_date.items(), key=lambda x:x[1][1])
        

        # content_types = msg_str.get_content_maintype()
        # payload = trial_msg['payload']
        # headers = payload.get("headers")
        # parts = payload.get("parts")
        # folder_name = "email"
        # messages = unread_msgs.get('messages', []) #idk what tis does
        # message_bodies = [service.users().messages().get(userId='me', id=msg['id']).execute() for msg in messages]


        # TODO fix
        # sorted_senders = []
        # for key, val in sorted_unread_senders:
        #     sorted_senders.append({"Sender": key, "Number": val})

        # emailID => subject, date, summary. there's got to be a better or at least more organized way
        ids = []
        subjects = []
        dates = []
        summaries = []
        for key, val in sorted_unread_emails:
            ids.append(key)
            subjects.append(val[0])
            dates.append(val[1])
            summaries.append(val[2])
        
        context = {}
        context["num_ids"] = len(ids)
        context["top_unread_senders"] = sorted_unread_senders
        context["email_ids"] = ids
        context["subjects"] = subjects
        context["dates"] = dates
        context["summaries"] = summaries
        
        
    except HttpError as error:
        # TODO(developer) - Handle errors from gmail API.
        print(f'An error occurred: {error}')

    return flask.render_template("index.html", **context)

def find_email_dates(email_id, email_content): # return datetime
    email_text = re.sub(r'\[[0-9]*\]', ' ', email_content)
    email_text = re.sub(r'\s+', ' ', email_text)
    email_text = re.sub(r'^https?:\/\/.*[\r\n]*', '', email_text, flags=re.MULTILINE)
    # email_text_links_removed = re.findall() use this to find dates
    email_text_list = email_text.split()

    # use regex for Jan, Jan. , 1, 01 etc
    months = ["January", "Feb", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]
    months_struct = {"January": 1, "Feb": 2, "March": 3, "April": 4, "May": 5, "June": 6, "July": 7, "August": 8, "September": 9, "October": 10, "November": 11, "December": 12}
    
    dates = []
    
    for month in months:
        try:
            idx = email_text_list.index(month)
            month_val = email_text_list[idx]
            day = email_text_list[idx+1]
            day = day[:(len(day)-1)] # get rid of comma. careful for single digit
            year = email_text_list[idx+2]

            if not day.isnumeric() or int(day) > 31:
                print(day)
                day = 28
            if not year.isnumeric():
                year = 2023
            
            d = datetime.datetime(year=int(year),month=months_struct[month_val], day=int(day))
            if(d >= datetime.datetime.today()):
                dates.append(d)
        
        except ValueError:
            continue
        
        if(len(dates) > 0):
            return min(dates)
        return datetime.datetime(year=datetime.MAXYEAR,month=1, day=31)
            



def process_email(email_content):
    # Removing Square Brackets and Extra Spaces
    article_text = re.sub(r'\[[0-9]*\]', ' ', email_content)
    article_text = re.sub(r'\s+', ' ', article_text)

    # article_text is for creating summary text
    # formatted_article_text is for calcs
    # Removing special characters and digits
    formatted_article_text = re.sub('[^a-zA-Z]', ' ', article_text )
    formatted_article_text = re.sub(r'\s+', ' ', formatted_article_text)

    sentence_list = nltk.sent_tokenize(article_text)

    stopwords = nltk.corpus.stopwords.words('english')

    word_frequencies = {}
    for word in nltk.word_tokenize(formatted_article_text):
        if word not in stopwords:
            if word not in word_frequencies.keys():
                word_frequencies[word] = 1
            else:
                word_frequencies[word] += 1

    try:
        maximum_frequncy = max(word_frequencies.values())
    except:
        return ""

    for word in word_frequencies.keys():
        if word[:8] != "https://":
            word_frequencies[word] = (word_frequencies[word]/maximum_frequncy)

    sentence_scores = {}
    for sent in sentence_list:
        for word in nltk.word_tokenize(sent.lower()):
            if word in word_frequencies.keys():
                if len(sent.split(' ')) < 30:
                    if sent not in sentence_scores.keys():
                        sentence_scores[sent] = word_frequencies[word]
                    else:
                        sentence_scores[sent] += word_frequencies[word]

    summary_sentences = heapq.nlargest(7, sentence_scores, key=sentence_scores.get)

    summary = ' '.join(summary_sentences)

    return summary
