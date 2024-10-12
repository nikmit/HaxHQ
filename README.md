License: GNU GPLv3

This is an open source project I have been working on in my free time.
At present, it can import nessus and pingcastle reports, review, merge and delete issues (amend descriptions DIEs etc) and create a report in the standard format as output by Dradis - except a good bit better and faster.

There is lots to be done on it still, and the ONLY focus so far has been getting it to the point where it can be used for reporting. I have built my last to reports with it and it saved me a lot of time, but it is insecure, not very user friendly and more than likely buggy. Run on localhost only, don't expose externally. Work in (slow) progress.


## To Run the App:

 - source the virtual environment
    ```bash
    $ source venv/bin/activate
    ```
 - start postgresql
    - Native:
        TODO
    - Docker:
        ```bash
        $ cd postgres-docker
        postgres-docker $ docker-compose up -d
        Starting my_postgres ... done
        postgres-docker $ docker exec -it my_postgres psql -U flask -d xhq -f /schema.sql
        ...
        ...
        postgres-docker $ docker exec -it my_postgres psql -U flask -d xhq -f /library.sql
        ```
 - start the app
    ```bash
    $ ./start-app
    * Serving Flask app "app.py" (lazy loading)
    * Environment: development
    * Debug mode: on
    * Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)
    * Restarting with stat
    * Debugger is active!
    * Debugger PIN: 123-123-123
    ```

