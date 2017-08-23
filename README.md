Bissell
=======

The poor person's iRobot. 

Intended for testing iRobot clients before the server is ready. 

Current status is that all iRobot endpoints are supported, but many return Not Implemented status.

Requests for data objects that end in `.cram` or `.crai` are fulfilled using test data, and all other paths result in a 404 error. 

A dockerfile is included (which includes the ~6MB test CRAM and its index). To run:
```
docker run -p 5000:5000 -it mercury/bissell
```

