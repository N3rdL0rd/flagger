import sys
import json
import argparse
import schedule
import time
from tqdm import tqdm
import requests
from ollama import chat
from ollama import ChatResponse
from typing import List, Optional, Dict, Any
from .sniffers import *
from .backends import *
from textwrap import dedent
from rapidfuzz import fuzz
import datetime
from .globals import VERSION
import traceback
import os

FOUND_THIS_SESSION = set()

def log_to_file(msg: str):
    with open("log.txt", "a") as f:
        f.write(msg + "\n")

def discord_embed(chall: str, url: str, flag: str, endpoint: str, ctf: str) -> None:
    data = {
        "embeds": [
            {
                "title": "Potential flag found!",
                "description": f"```\n{flag}\n```",
                "color": 4321431,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "footer": {
                    "text": "flagger " + VERSION
                },
                "fields": [
                    {
                        "name": "For chall:",
                        "value": chall
                    },
                    {
                        "name": "From URL:",
                        "value": url
                    },
                    {
                        "name": "For CTF:",
                        "value": ctf
                    }
                ]
            }
        ]
    }
    requests.post(endpoint, json=data)
    
def discord_small_embed(title: str, url: str, flag: str, endpoint: str, ctf: str) -> None:
    data = {
        "embeds": [
            {
                "title": title,
                "description": f"```\n{flag}\n```",
                "color": 4321431,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "footer": {
                    "text": "flagger " + VERSION
                },
                "fields": [
                    {
                        "name": "From URL:",
                        "value": url
                    },
                    {
                        "name": "For CTF:",
                        "value": ctf
                    }
                ]
            }
        ]
    }
    requests.post(endpoint, json=data)

def discord_status_embed(msg: str, endpoint: str) -> None:
    data = {
        "embeds": [
            {
                "title": "valgrind flagger status",
                "description": msg,
                "color": 4321431,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "footer": {
                    "text": "flagger " + VERSION
                }
            }
        ]
    }
    requests.post(endpoint, json=data)

def log_flag(flag: Flag, config: Dict[str, Any], challenges: List[str], global_config: Dict[str, Any], name: str):
    if flag.flag in FOUND_THIS_SESSION:
        return
    with open("flags.txt", "a") as f:
        f.write(flag.flag + "\n")
        # try a text match first
        matches = []
        for challenge in challenges:
            if flag.context.lower().find(challenge.lower()) != -1:
                # append one for each occurence
                for _ in range(flag.context.lower().count(challenge.lower())):
                    matches.append(challenge)
        for challenge in challenges:
            if fuzz.ratio(flag.context, challenge) > 80:
                matches.append(challenge)
                break
        if (not matches or len(matches) > 1) and config['use_llm'] == True:
            matches = []
            for _ in range(2): # 2 attempts to get a valid result
                print(" Falling back to LLM to classify...")
                response: ChatResponse = chat(model='dolphin-mistral', messages=[
                    {
                        'role': 'system',
                        'content': 'You are a helpful assistant chatbot for CTF competitions.'
                    },
                    {
                        'role': 'user',
                        'content': dedent(f"""Here is a flag and its context:

                                              ```plaintext
                                              Flag: {flag.flag}
                                              Origin: {flag.origin}
                                              Context: 
                                              {flag.context}
                                              ```

                                              Here is a list of challenges:
                                              ```plaintext
                                              {", ".join(challenges)}
                                              ```

                                              Out of the list of challenges, provide ONE challenge that you think this flag belongs to. Respond ONLY with the challenge name in a code block, do not include any other information. Eg:

                                              ```
                                              {challenges[0]}
                                              ```

                                              or

                                              ```
                                              {challenges[1]}
                                              ```

                                              etc...

                                              If it does not seem to match, respond with "FALSE POSITIVE" in a code block instead.
                                              """)
                    },
                ])
                msg = response.message.content
                for challenge in challenges:
                    if challenge.lower() in msg.lower():
                        matches.append(challenge)
                        break
                if "FALSE POSITIVE" in msg or matches:
                    break
        if not matches:
            log_to_file(f"Flag: {flag.flag} Origin: {flag.origin} Challenge: Unknown")
            discord_embed("Unknown challenge", flag.origin, flag.flag, global_config['keys']['discord_webhook'], name)
        else:
            # sort matches by how many times they appear in the context
            matches.sort(key=lambda challenge: flag.context.lower().count(challenge.lower()), reverse=True)
            log_to_file(f"Flag: {flag.flag} Origin: {flag.origin} Challenge: {matches[0] if matches else 'Unknown'}")
            if global_config['use_discord_webhook']:
                discord_embed(matches[0], flag.origin, flag.flag, global_config['keys']['discord_webhook'], name)
        FOUND_THIS_SESSION.add(flag.flag)

def dispatch(sniffers: List[Sniffer], backend: Optional[Backend], challenges: Optional[List[str]], global_config: Dict[str, Any], name: str):
    print("Searching...")
    flags = []
    for sniffer in tqdm(sniffers):
        try:
            flags += sniffer.sniff()
        except Exception as e:
            print(f"Error in {sniffer.__class__.__name__}: {e}")
            traceback.print_exc()
            continue
    flags = consolidate_flags(flags)
    for flag in tqdm(flags):
        log_flag(flag, sniffer.config, backend.get_challenges() if backend else challenges, global_config, name)

def main():
    parser = argparse.ArgumentParser(description="valgrind's internal flag sniffer (what, me? unethical? never...)")
    parser.add_argument('config', type=argparse.FileType('r'), help='path to the config file')
    parser.add_argument('name', help='name of the ctf to sniff for')
    parser.add_argument('-t', "--test", action="store_true", help="run all sniffers once and exit")
    args = parser.parse_args()
    config = json.load(args.config)
    if not args.name in config:
        print(f"CTF {args.name} not found in config")
        sys.exit(1)
    glob = config["global"]
    config = config[args.name]
    print("Loading sniffers...")
    sniffers = []
    for sniffer in ALL_SNIFFERS:
        sniffers.append(sniffer(glob, config))
    print("Using backend: " + config["backend"]["type"])
    backend: Optional[Backend] = None
    match config["backend"]["type"]:
        case "other":
            print("config.challenges should be updated with a list of strings for each challenge's name.")
        case "ctfd":
            backend = CtfdBackend(config["backend"]["url"], config["backend"]["token"])
        case "0ctf":
            backend = ZeroCtfBackend(config["backend"]["url"]) 
        case "ctfx":
            backend = CtfxBackend(config["backend"]["url"], config["backend"]["username"], config["backend"]["password"])
        case _:
            print("Invalid backend type")
            sys.exit(1)
    if backend is None and not config.get("challenges"):
        print("No backend or challenges found. Please update config.challenges to contain a list of strings for each challenge's name.")
        sys.exit(1)
    print(f"Sniffing for {args.name} with flag format r'{config['flag_re']}'...")
    if glob['use_discord_webhook']:
        discord_status_embed(f"starting up for ctf {args.name}, flag format: \n```\n{config['flag_re']}\n```", glob['keys']['discord_webhook'])
    # load previously found flags
    if os.path.exists(f"flags_found_{args.name}.txt"):
        with open(f"flags_found_{args.name}.txt", "r") as f:
            for line in f:
                FOUND_THIS_SESSION.add(line.strip())
    print("Press Ctrl+C to exit")
    if args.test:
        dispatch(sniffers, backend, config.get("challenges"), glob, args.name)
        sys.exit(0)
    schedule.every(glob["interval"]).seconds.do(dispatch, sniffers, backend, config.get("challenges"), glob, args.name)
    try:
        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        print("Bye!")
        if glob['use_discord_webhook']:
            discord_status_embed("shutting down.", glob['keys']['discord_webhook'])
        with open(f"flags_found_{args.name}.txt", "w") as f:
            for flag in FOUND_THIS_SESSION:
                f.write(flag + "\n")
    sys.exit(0)
    
if __name__ == '__main__':
    main()