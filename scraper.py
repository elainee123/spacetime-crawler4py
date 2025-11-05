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

def is_num(number):
    cleaned_num = number.replace("{", "").replace(",", "").replace("}", "").replace(".", "").replace("-", "").replace("(", "").replace(")", "").replace("$", "").replace("%", "")
    return cleaned_num.isdigit()

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
        with open('URL_Length.txt', 'a') as file:
            file.write("Words: ERROR, "+ str(resp.status) + " " + " URL: " + resp.url + '\n')
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
            with open('URL_Length.txt', 'a') as file:
                file.write("Words: Empty" + " URL: " + resp.url + '\n')
            return link_list
    except Exception as e:
        print("Error parsing HTML: ", e)
        with open('URL_Length.txt', 'a') as file:
            file.write("Words: ERROR!" + " URL: " + resp.url + '\n')
        return link_list

    # Gets the hyperlink out of tree
    etree.strip_elements(tree, 'script', 'style', 'noscript', 'meta', 'link', 'header', 'footer', with_tail = False)
    raw_words = " ".join(tree.itertext())
    raw_links = tree.xpath("//a/@href")
    raw_links_num += len(raw_links)

    raw_words = raw_words.split()

    numeric_words = sum(1 for word in raw_words if is_num(word))
    num_total_words = len(raw_words)
    percent_numeric = numeric_words / num_total_words if num_total_words > 0 else 0
    if percent_numeric > .8:
        with open('URL_Length.txt', 'a') as file:
            file.write("Words: Dataset!" + " URL: " + resp.url + '\n')
        return link_list
    with open('file_words.txt', 'a') as file:
        file.write(resp.url +  '\n' + str(len(raw_words)) + " " + str(raw_words) + '\n')

    with open('URL_Length.txt', 'a') as file:
        file.write("Words: " + str(len(raw_words)) + " URL: " + resp.url + '\n')

    
    
    for i in raw_links:
        # if i not in url_already_parsed:
        # urljoin detects if i is a page directory instead of an absolute link and reconnects it
        try:
            abs_link = urljoin(resp.url, i)
        except: 
            continue
        abs_link = urlparse(abs_link)



        # abs_link = abs_link.split("#")[0]
        query = parse_qsl(abs_link.query)

        bad_queries = {'utm_source', 'ref', 'session', 'sort', 'filter', 'Keywords', 'search', 'order', 'utm_medium', 'utm_campaign', 
        'q', 'search', 'from', 'share', 'ref_type', 'entry_point', 'outlook-ical', 'redirect_to', 'tab_files', 'tab_details', 'image', 
        'redirect_to_referer', 'format', 'ical', 'src', 'rev', 'C', 'do', 'ns', 'idx'}

        new_query = []

        for (key, value) in query:
            if key not in bad_queries:
                new_query.append((key,value))
        
        new_query = urlencode(new_query)

        abs_link = urlunparse(abs_link._replace(query = new_query))
        abs_link = abs_link.split('#')[0]

        # gets rid of all repeated links and invalid links
        if (is_valid(abs_link)):
            if abs_link not in url_already_parsed:
                url_already_parsed.add(abs_link)
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



url_current = ""
unqiue_hostname = set()
def is_valid(url):
    global url_current, unqiue_hostname
    
    # print("IS VALI/D CHECKING " + str(check))
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.


    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False

        accept_hostnames = [
            r".*\.?ics\.uci\.edu$",
            r".*\.?cs\.uci\.edu$",
            r".*\.?informatics\.uci\.edu$", 
            r".*\.?stat\.uci\.edu$",
        ]

        valid_hostname = False

        if "version=" in parsed.query or "action=diff" in parsed.query or "from=" in parsed.query or "date=" in parsed.query or "day=" in parsed.query or "ns=" in parsed.query or "do=" in parsed.query or "idx=" in parsed.query:
            return False

        bad_paths = ('login', 'account', 'private', 'portal', 'timeline', 
        'calendar', 'commit', 'forks', 'raw-attachment', 'tree', 
        'branches', 'do', 'join', 'register', 'auth', 'pix', 'randomSmiles100K')
        if ('events' in parsed.path.lower() and re.search(r'\d{4}-\d{2}', parsed.path)):
            return False
        
        path_segments = [segment.lower() for segment in parsed.path.strip('/').split('/')]
        if parsed.path.startswith('/~wjohnson'):
            if any('data' in segment for segment in path_segments):
                return False
        else:
            if any(segment in bad_paths for segment in path_segments):
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
