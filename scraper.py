import re
from lxml import etree
from urllib.parse import urlparse, urljoin, parse_qsl, urlunparse, urlencode
# receives a URL and corresponding Web response. parse the web response, extract enough information from the page
# to be able to answer the questions for the report
# lastly, return the list of URLs scapped
def scraper(url, resp):
    links = extract_next_links(url, resp)
    return links

num_links = 0
file_call = 0
url_already_parsed = set()
raw_links_num = 0
def extract_next_links(url, resp):
    print("\n\n" + resp.url + "\n\n")
    global num_links, file_call, raw_links_num, unqiue_hostname


    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content
    file_call += 1
    link_list = set()

    if (resp.status != 200):
        print("Problem getting page.")
        return link_list

        # test
    
    decode_site = resp.raw_response.content.decode('utf-8', errors = 'ignore')

    # makes sure that HTML is fully formed and doesn't have any issues
    parser = etree.HTMLParser()
        
    try: 
        # makes a tree that now allows html attributes to be attainable 
        tree = etree.fromstring(decode_site, parser)
        if tree is None:
            print("Error tree is none.")
            return link_list
    except Exception as e:
        print("Error parsing HTML: ", e)
        return link_list

    # Gets the hyperlink out of tree
    raw_words = " ".join(tree.itertext())
    raw_links = tree.xpath("//a/@href")
    raw_links_num += len(raw_links)

    raw_words = raw_words.split()

    with open('URL_Length.txt', 'a') as file:
        file.write("Words: " + str(len(raw_words)) + " URL: " + resp.url + '\n')

    if (len(raw_words) < 300):
        return list()
    
    
    
    for i in raw_links:
        # if i not in url_already_parsed:
        # urljoin detects if i is a page directory instead of an absolute link and reconnects it
        try:
            abs_link = urljoin(resp.url, i)
        except: 
            print('error')
            return list()
        abs_link = urlparse(abs_link)



        # abs_link = abs_link.split("#")[0]
        query = parse_qsl(abs_link.query)

        bad_queries = {'utm_source', 'ref', 'session', 'sort', 'filter', 'Keywords', 'search', 'order', 'utm_medium', 'utm_campaign', 
        'q', 'search', 'from', 'share', 'ref_type', 'entry_point', 'outlook-ical', 'redirect_to', 'tab_files', 'tab_details', 'image', 
        'ns', 'do', 'idx', 'redirect_to_referer', 'format', 'ical', 'src', 'C', 'id', 'action'}

        new_query = []

        for (key, value) in query:
            if key not in bad_queries:
                new_query.append((key,value))
        
        new_query = urlencode(new_query)

        abs_link = urlunparse(abs_link._replace(query = new_query))
        abs_link = abs_link.split('#')[0]

        # gets rid of all repeated links and invalid links
        if abs_link not in url_already_parsed:
            url_already_parsed.add(abs_link)
            if (is_valid(abs_link)):
                print(abs_link)
                link_list.add(abs_link)
    
    
    num_links += len(link_list)

    # data about the scan 
    print("Length of Page: " + str(len(raw_words)))
    print("Repeated Links: " + str(len(url_already_parsed)))    
    print("Raw links: " + str(raw_links_num))
    print("Links: " + str(num_links))
    print("File called: " + str(file_call))
    print("Unqiue host called: " + str(len(unqiue_hostname)))
    return list(link_list)



check = 0
url_current = ""
unqiue_hostname = set()
def is_valid(url):
    global url_current, check, unqiue_hostname
    check += 1
    
    # print("IS VALI/D CHECKING " + str(check))
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.


    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False

        accept_hostnames = [
            r".*\.ics\.uci\.edu$",
            r".*\.cs\.uci\.edu$",
            r".*\.informatics\.uci\.edu$", 
            r".*\.stat\.uci\.edu$",
        ]

        valid_hostname = False

        if "version=" in parsed.query or "action=diff" in parsed.query or "from=" in parsed.query or "date=" in parsed.query or "day=" in parsed.query:
            return False

        bad_paths = ('/login', '/account', '/private', '/portal', '/search', '/timeline', 
        '/calendar', '/~dechter', '/commit', '/forks', '/events/', '/raw-attachment', '/tree', 
        '/branches','/event', '/-/')
        if parsed.path.startswith(bad_paths) or '/commit/' in parsed.path or '/pix/' in parsed.path:
            return False
            
        if parsed.netloc.endswith('gitlab.ics.uci.edu') and (parsed.path and parsed.path != '/'):
            return False

        
        # actual one

        for link in accept_hostnames:
            if not parsed.hostname:
                return False
            if re.match(link, parsed.hostname):
                if parsed.hostname not in unqiue_hostname:
                    unqiue_hostname.add(parsed.hostname)
                    with open('unqiue_host.txt', 'a') as file:
                        file.write("Hostname: " + parsed.hostname + '\n')
                valid_hostname = True

        return ((not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names|ppsx|ppt"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())) and valid_hostname) 

        

    except TypeError:
        print ("TypeError for ", parsed)
        raise
