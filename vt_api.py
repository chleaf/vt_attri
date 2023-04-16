import requests
import json
import csv

VT_KEY = 'key\\vt_key.txt'
VT_API_URL = "https://www.virustotal.com/api/v3/files/"

CONTACTED_DOMAIN_URL = "/contacted_domains"
CONTACTED_IP_URL = "/contacted_ips"
CONTACTED_URL_URL = "/contacted_urls"

IOC_TYPE = ['domain', 'ip', 'url']
HEADER_ROW= ['IOC', 'Malicious Attributes', 'Non-Malicious Attributes', 'Reference']
PARAMA = { 'limit': 200 } # The limit is the attributes that can print out. By default is 10

def get_vt_key():
    with open(VT_KEY) as file:
        return {'x-apikey': file.read()}

def get_contacted_attributes(hash, attrb_type, url):
    #It will send request for its attributes and return the result weather it is malicious or non-malicious attributes
    response = requests.get(url, headers=get_vt_key(), params= PARAMA)

    malicious_attributes = attrb_type + ":\n" 
    non_malicious_attributes = attrb_type + ":\n" 

    if response.status_code == 200:
        #If there is no attributes found in VT
        if len(response.json()['data']) == 0:
            malicious_attributes += "No attributes found\n"
            non_malicious_attributes += "No attributes found\n"
        

        for attributes in response.json()['data']:
            #add the type of attributies found
            if attributes['type'] == 'url':
                attributes_ioc = attributes['context_attributes']['url']
            else:
                attributes_ioc = attributes['id']

            #Seperate the attributes IOC of the malicious and non-malicious 
            if attributes['attributes']['last_analysis_stats']['malicious'] > 0:
                malicious_attributes += attributes_ioc + "\n"
            else:
                non_malicious_attributes += attributes_ioc + "\n"
        return malicious_attributes, non_malicious_attributes
    else:
        #IOC not found from VT
        malicious_attributes += "IOC Not found\n"
        non_malicious_attributes += "IOC Not found\n"
        return malicious_attributes, non_malicious_attributes
    
def main():
    #Open ioc file and retrive all the ioc hashes
    with open('ioc.txt', 'r') as file:
        ioc = file.read().splitlines()
    
    #Open the CSV file and run get_contacted_attributes() to get the VT realtions result to csv
    with open('output.csv', 'w', newline='', encoding='utf-8') as output_file:
        writer = csv.writer(output_file)
        writer.writerow(HEADER_ROW)
    
        #For every hash, it will find its contacted ips, domain and url from VT Relations
        # https://www.virustotal.com/gui/file/<hash>/relations
        ioc_ran = 0
        for hash in ioc:
            ioc_ran += 1
            print("[" + str(ioc_ran) +  "/" + str(len(ioc)) +  "] Getting VT Relation from " + hash)
            refernce_url = 'https://www.virustotal.com/gui/file/' + hash
            row_data = [hash, "", "", refernce_url]
            for types in IOC_TYPE:
                if types == 'domain':
                    url = VT_API_URL + hash + CONTACTED_DOMAIN_URL
                elif types == 'ip':
                    url = VT_API_URL + hash + CONTACTED_IP_URL
                else:
                    url = VT_API_URL + hash + CONTACTED_URL_URL
                
                mal_attri, non_mal_atti = get_contacted_attributes(hash, types, url)
                row_data[1] += mal_attri + "\n"
                row_data[2] += non_mal_atti + "\n"
            
            #All results from the relation will be added to the csv file output.csv
            writer.writerow(row_data)

if __name__ == '__main__':
    main()