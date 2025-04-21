from boofuzz import *
from boofuzz.connections import UDPSocketConnection

host_ip = '192.168.16.254'

def fuzzing_main():
    session = Session(target=Target(connection=UDPSocketConnection(host_ip, 6000)),
                      reuse_target_connection=True, 
                      fuzz_db_keep_only_n_pass_cases=10)
    fuzzing_define_proto(session=session)
    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="UDP payload")
    with s_block("UDP"):
        s_string(value="bye", name="Data")

    session.connect(s_get('UDP payload'))


if __name__ == "__main__":
    fuzzing_main()
