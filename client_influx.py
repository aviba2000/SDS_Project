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
    query = '''
        SELECT *
        FROM unhandled_packets
        WHERE time < '{}'
        AND src_port = 22
    '''.format(time_str)

    result = client.query(query)

    # Convert result to list of dictionary
    for elem in result.get_points():
        print(elem)

    # unique_flows = set()
    # for point in points:
    #     print('src_addr: ', point["src_addr"])
    #     dst_addr = point["dst_addr"]
    #     src_addr = point["src_addr"]

    #     unique_flows.add(
    #         (dst_addr, src_addr)
    #     )

    # # Conver set to array of dictionary
    # unique_list = []
    # for flow in unique_flows:
    #     unique_list.append({
    #         "dst_addr": flow[0],
    #         "src_addr": flow[1]
    #     })

if __name__ == '__main__':
    main()