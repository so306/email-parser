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
import flask
import my_parser

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

senders = {}

@my_parser.app.route("/") # methods=['GET'])
def main():
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

    
    emailid_to_subject = {}
    sorted_unread_senders = []

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
            print(type(payload))

            unreads_headers = payload['headers']

            for header in unreads_headers:
                if(header['name'] == 'Subject'):
                    print("Subject", header['value'])
                    emailid_to_subject[email_id] = header['value']
                if header['name'] == 'From':
                    if header['value'] not in senders:
                        senders[header['value']] = 1
                    else:
                        senders[header['value']] += 1

        sorted_unread_senders = sorted(senders.items(), key=lambda x:x[1], reverse=True)
        # out of _(#100?)__ most recent unread emails, ___


        message_list_raw = service.users().messages().get(userId='me', id=ids_unread_msgs[3], format='raw').execute()
        msg_raw = base64.urlsafe_b64decode(message_list_raw['raw'].encode('ASCII'))
        msg_str = email.message_from_bytes(msg_raw)
        # print(msg_str.get("Content-Type"))
        # print(msg_str.get_body('related', 'html', 'plain'))
        str_msg = msg_str.as_string()
        idx_plain = str_msg.find("Content-Type: text/plain")
        idx_html = str_msg.find("Content-Type: text/html")
        email_content = str_msg[idx_plain:idx_html]
        # print(email_content)

        # content_types = msg_str.get_content_maintype()
        # print(content_types)
        # print(msg_str)
        
        # payload = trial_msg['payload']
        # headers = payload.get("headers")
        # parts = payload.get("parts")
        # folder_name = "email"
        # print(payload)

        # messages = unread_msgs.get('messages', []) #idk what tis does

        # message_bodies = [service.users().messages().get(userId='me', id=msg['id']).execute() for msg in messages]
        # print("hi",message_bodies[0])
        # for msg in message_bodies:
        #     print(msg)


        # all_msgs = service.users().messages().list(userId='me').execute()
        # # print(unread_msgs['messages']) what is this even getting
        # arr = [msg for msg in unread_msgs: if msg['id'] in ]
        # print(arr[0]["raw"])



        # all_messages = service.users().messages().list(userId='me').execute()
        # print(all_messages)
        # unread_messages = [msg for msg in all_messages.labelIds
        #         if msg == "UNREAD"]
        # print(unread_messages)


        context = {}
        context["sorted_unread_senders"] = sorted_unread_senders
        context["emailid_to_subject"] = emailid_to_subject

    except HttpError as error:
        # TODO(developer) - Handle errors from gmail API.
        print(f'An error occurred: {error}')

    return flask.render_template("index.html", **context)


if __name__ == '__main__':
    main()