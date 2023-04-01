import json
import matplotlib.pyplot as plt
import numpy as np
from Crypto.Util.number import long_to_bytes

data = json.load(open("weather.json", 'rt'))["hourly"]['data']

temp = [x['temperature'] for x in data]
hum = [x['humidity'] for x in data]
wsp = [x['windSpeed'] for x in data]
cloud = [x['cloudCover'] for x in data]
ozone = [x['ozone'] for x in data]

def save_json(l, name):
    with open(f"{name}.json", "wt") as f:
        json.dump(l, f)


save_json(temp, "temperature")
save_json(hum, "humidity")
save_json(wsp, "windspeed")
save_json(cloud, "cloudcover")
save_json(ozone, "ozone")

data = [(x / 400 + 3 * y) * (256.0 / 3.5) for x, y in zip(ozone, cloud)]

print(sorted(cloud))
print(sorted(hum))


def hist(data, xl, yl, title):
    plt.clf()
    n, bins, pathes = plt.hist(x=data, bins='auto', color='blue', alpha=0.7, rwidth=0.85)
    
    plt.grid(axis='y', alpha=0.75)
    plt.xlabel(xl)
    plt.ylabel(yl)
    plt.title(title)
    
    maxfreq = n.max()
    plt.ylim(ymax=np.ceil(maxfreq/10)*10 if maxfreq % 10 else maxfreq + 10)
    plt.savefig(title)


hist(temp, 'Temperature', 'Freq', 'TempFreq')
hist(hum, 'Humidity', 'Freq', 'HumFreq')
hist(wsp, 'WindSpeed', 'Freq', 'WindSpeedFreq')
hist(cloud, 'CloudCover', 'Freq', 'CloudCoverFreq')
hist(ozone, 'Ozone', 'Freq', 'OzoneFreq')
hist(data, "Mix", "Freq", "MixFreq")

res_hkdf = json.load(open("res.json"))
hist(res_hkdf, "10Bits", "Freq", "BitsHKDFFreq")

passes = json.load(open("passwords.json"))
passes = [ord(x[0]) >> 3 for x in passes]
hist(passes, "5Bits", "Freq", "BitsPasswordsFreq")

res_pbkdf2 = json.load(open("pass_res.json"))
hist(res_pbkdf2, "10Bits", "Freq", "BitsPBKDF2Freq")
