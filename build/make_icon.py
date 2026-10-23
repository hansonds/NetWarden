from PIL import Image, ImageDraw
import sys
S=1024
img=Image.new("RGBA",(S,S),(0,0,0,0))
# gradient shield
grad=Image.new("RGBA",(S,S))
gd=ImageDraw.Draw(grad)
for i in range(S):
    t=i/S
    c=(int(0x3B+(0x1B-0x3B)*t),int(0x7B+(0xC6-0x7B)*t),int(0xFF+(0xE8-0xFF)*t),255)
    gd.line([(0,i),(S,i)],fill=c)
def bez(p0,p1,p2,p3,n=60):
    pts=[]
    for k in range(n+1):
        t=k/n;u=1-t
        pts.append((u**3*p0[0]+3*u*u*t*p1[0]+3*u*t*t*p2[0]+t**3*p3[0], u**3*p0[1]+3*u*u*t*p1[1]+3*u*t*t*p2[1]+t**3*p3[1]))
    return pts
s=S
pts=bez((.5*s,.04*s),(.68*s,.14*s),(.84*s,.16*s),(.92*s,.16*s))+bez((.92*s,.16*s),(.94*s,.58*s),(.78*s,.82*s),(.5*s,.97*s))+bez((.5*s,.97*s),(.22*s,.82*s),(.06*s,.58*s),(.08*s,.16*s))+bez((.08*s,.16*s),(.16*s,.16*s),(.32*s,.14*s),(.5*s,.04*s))
mask=Image.new("L",(S,S),0); ImageDraw.Draw(mask).polygon(pts,fill=255)
img.paste(grad,(0,0),mask)
d=ImageDraw.Draw(img); w=int(s*.085)
def line(a,b):
    d.line([a,b],fill="white",width=w)
    for p in (a,b): d.ellipse([p[0]-w/2,p[1]-w/2,p[0]+w/2,p[1]+w/2],fill="white")
line((.37*s,.28*s),(.37*s,.70*s)); line((.25*s,.58*s),(.37*s,.70*s)); line((.37*s,.70*s),(.49*s,.58*s))
line((.63*s,.70*s),(.63*s,.28*s)); line((.51*s,.40*s),(.63*s,.28*s)); line((.63*s,.28*s),(.75*s,.40*s))
img.save(sys.argv[1],sizes=[(16,16),(24,24),(32,32),(48,48),(64,64),(128,128),(256,256)])
img.resize((256,256),Image.LANCZOS).save(sys.argv[2])
