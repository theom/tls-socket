# tls-socket
A Botan TLS socket wrapper.

For a quick overview of the code, see my blog [Botan TLS Socket Wrapper](http://blog.axonehf.com/?p=1)

# Building

If you have [`tup`](http://gittup.org/tup/) you can just do:

```
tup init
tup
```

If not then just run:

```
./build.sh
```

This creates two executable: `server` and `client`. Run the server in one terminal and the client in another and once the client has connected everything you type will be echoed back. Easy!
