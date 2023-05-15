from influxdb import InfluxDBClient
import datetime

def setup_client():
    # Set up a client object
    client = InfluxDBClient(host='localhost', port=8086)

    # Use RYU as the database
    client.switch_database('RYU')

    return client

def main(): 
    client = setup_client()

    # Attacker IP
    attacker_ip = '10.0.0.2'

    # Current time with python datetime
    current_time = datetime.datetime.now()
    time_str = current_time.strftime('%Y-%m-%dT%H:%M:%SZ')

    # Query where time is less than current time
    # query = 'SELECT * FROM unhandled_packets WHERE time < \'{}\' AND dst_addr = \'{}\''.format(time_str, attacker_ip)
    query = 'SELECT * FROM unhandled_packets WHERE time < \'{}\''.format(time_str)

    result = client.query(query)

    # Get results
    points = list(result.get_points(measurement='unhandled_packets'))

    for point in points:
        print(point)

if __name__ == '__main__':
    main()