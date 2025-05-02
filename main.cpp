#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

class Gadget {
public:
  Gadget(const char *hostname);
};

class BarrierClient {
public:
  BarrierClient(const char *host, uint16_t port, const char *client_name);
  void loop();
  void handle_packet(uint32_t length, const char *buffer);
  void hangup();
  void key_down(struct key_packet &evt);
  void key_up(struct key_packet &evt);
  void mouse_move(uint16_t x, uint16_t y);
  void mouse_button(int button, int down);
private:
  void reconnect();

  struct sockaddr_in server;
  int sock;
  const char *client_name;
  int keyb_gadget;
  int mouse_gadget;
  uint8_t k_report[8];
  uint8_t m_report[6];
};

BarrierClient::BarrierClient(const char *host, uint16_t port, const char *client_name) : client_name(client_name) {
  server.sin_family = AF_INET;
  server.sin_port = htons(port);
  inet_aton(host, &server.sin_addr);

  memset(k_report, 0, 8);
  memset(m_report, 0, sizeof(m_report));

  keyb_gadget = open("/dev/hidg0", O_RDWR);
  mouse_gadget = open("/dev/hidg1", O_RDWR);
  reconnect();
}

void BarrierClient::hangup() {
  puts("server hung up");
}

void BarrierClient::reconnect() {
  sock = socket(AF_INET, SOCK_STREAM, 0);
  connect(sock, (sockaddr*)&server, sizeof(server));
}

const char handshake[] = "Barrier\0\x1\0\x6";

struct dinfo {
  uint32_t length;
  char type[4];
  uint16_t x, y;
  uint16_t w, h;
  uint16_t warp_size;
  uint16_t cur_x, cur_y;
} __attribute__((packed));

struct mouse_move {
  char type[4];
  uint16_t x, y;
} __attribute__((packed));

struct key_packet {
  char type[4];
  uint16_t key_id;
  uint16_t key_modifier_mask;
  uint16_t key_button;
} __attribute__((packed));

void byteswap_key(struct key_packet *pkt) {
  pkt->key_id = ntohs(pkt->key_id);
  pkt->key_modifier_mask = htons(pkt->key_modifier_mask);
  pkt->key_button = htons(pkt->key_button);
}

extern const uint8_t id_to_hid[256];
extern const uint8_t button_to_hid[256];

int get_modifier(int button) {
  if (button == 37) return 0x1; // left ctrl
  else if (button == 50) return 0x2; // left shift
  else if (button == 62) return 0x20; // right shift
  else if (button == 64) return 0x4;
  else if (button == 108) return 0x40;
  else return 0;
}

void BarrierClient::key_down(struct key_packet &evt) {
  uint8_t hid = 0;

  int mod = get_modifier(evt.key_button);

  if (mod) {
    k_report[0] |= mod;
    write(keyb_gadget, k_report, 8);
    return;
  }

  if (evt.key_button < 256) hid = button_to_hid[evt.key_button];

  if ((hid == 0) && (evt.key_id < 256)) {
    hid = id_to_hid[evt.key_id];
  }

  if (hid) {
    k_report[2] = hid;
    write(keyb_gadget, k_report, 8);
  } else {
    puts("unknown key");
  }
}

void BarrierClient::key_up(struct key_packet &evt) {
  int mod = get_modifier(evt.key_button);
  if (mod) {
    k_report[0] &= ~mod;
  }
  k_report[2] = 0;
  write(keyb_gadget, k_report, 8);
}

void BarrierClient::mouse_move(uint16_t x, uint16_t y) {
  *((uint16_t*)(m_report + 1)) = x;
  *((uint16_t*)(m_report + 3)) = y;
  write(mouse_gadget, m_report, sizeof(m_report));
}

void BarrierClient::mouse_button(int button, int down) {
  int bit = 0;
  if (button == 1) bit = 0;
  else if (button == 2) bit = 2;
  else if (button == 3) bit = 1;

  uint8_t value = 1<<bit;

  if (down) m_report[0] |= value;
  else m_report[0] &= ~value;
  write(mouse_gadget, m_report, sizeof(m_report));
}

void BarrierClient::handle_packet(uint32_t length, const char *buffer) {
  char outbuf[1024 + 1];
  if ((length == 11) && (memcmp(buffer, handshake, 11) == 0)) {
    puts("handshake detected");
    memcpy(outbuf+4, handshake, 11);
    uint32_t namelen = strlen(client_name);
    uint32_t namelen_be = htonl(namelen);
    memcpy(outbuf+4+11, &namelen_be, 4);
    memcpy(outbuf+4+11+4, client_name, namelen);
    uint32_t packet_len = htonl(11+4+namelen);
    memcpy(outbuf, &packet_len, 4);
    write(sock, outbuf, 4+11+4+namelen);
  } else if ((length == 4) && (memcmp(buffer, "QINF", 4) == 0)) {
    puts("query screen info");
    struct dinfo output;
    output.length = htonl(sizeof(output)-4);
    memcpy(output.type, "DINF", 4);
    output.x = 0;
    output.y = 0;
    output.w = htons(1920);
    output.h = htons(1080);
    output.warp_size = 0;
    output.cur_x = 0;
    output.cur_y = 0;
    write(sock, &output, sizeof(output));
  } else if ((length == 4) && (memcmp(buffer, "CIAK", 4) == 0)) {
    puts("info ack");
  } else if ((length == 4) && (memcmp(buffer, "CROP", 4) == 0)) {
    puts("client reset options");
  } else if ((length == 4) && (memcmp(buffer, "CALV", 4) == 0)) {
    //puts("client keep alive");
    uint32_t four = htonl(4);
    memcpy(outbuf, &four, 4);
    memcpy(outbuf+4, "CALV", 4);
    memcpy(outbuf+8, &four, 4);
    memcpy(outbuf+12, "CNOP", 4);
    write(sock, outbuf, 16);
  } else if ((length == 10) && (memcmp(buffer, "DKDN", 4) == 0)) {
    struct key_packet evt = *(const struct key_packet*)buffer;
    byteswap_key(&evt);
    printf("key down %d %d %d/0x%x\n", evt.key_id, evt.key_modifier_mask, evt.key_button, evt.key_button);
    key_down(evt);
  } else if ((length == 10) && (memcmp(buffer, "DKUP", 4) == 0)) {
    struct key_packet evt = *(const struct key_packet*)buffer;
    byteswap_key(&evt);
    printf("key up   %d %d %d\n", evt.key_id, evt.key_modifier_mask, evt.key_button);
    key_up(evt);
  } else if ((length == 5) && (memcmp(buffer, "DMDN", 4) == 0)) {
    mouse_button(buffer[4], 1);
  } else if ((length == 5) && (memcmp(buffer, "DMUP", 4) == 0)) {
    mouse_button(buffer[4], 0);
  } else if ((length == 8) && (memcmp(buffer, "DMMV", 4) == 0)) {
    const struct mouse_move *dmmv =(const struct mouse_move*)buffer;
    //printf("mouse move %04d,%04d\n", ntohs(dmmv->x), ntohs(dmmv->y));
    mouse_move(ntohs(dmmv->x), ntohs(dmmv->y));
  } else if ((length == 8) && (memcmp(buffer, "DMWM", 4) == 0)) { // wheel event
    int16_t x = ntohs(*(uint16_t*)(buffer+4));
    int16_t y = ntohs(*(uint16_t*)(buffer+6));
    printf("wheel %d %d\n", x, y);
  } else {
    char type[5];
    memcpy(type, buffer, 4);
    type[4] = 0;
    printf("unknown %d byte packet, code %s\n", length, type);
  }
}

void BarrierClient::loop() {
  char buffer[2048+1];
  while (true) {
    uint32_t l;
    int s = read(sock, &l, 4);
    if (s == 0) {
      hangup();
      return;
    }
    assert(s == 4);
    l = ntohl(l);
    //printf("size: %d\n", l);
    assert(l < 2048);
    s = read(sock, buffer, l);
    assert(l == s);
    buffer[s] = 0;
    //printf("%d '%s'\n", l, buffer);
    handle_packet(l, buffer);
  }
}

void writefile(const char *path, const char *contents) {
  int fd = open(path, O_WRONLY | O_CREAT, 0777);
  write(fd, contents, strlen(contents));
  close(fd);
}

void write_binary_file(const char *path, const unsigned char *contents, int length) {
  int fd = open(path, O_WRONLY | O_CREAT, 0777);
  write(fd, contents, length);
  close(fd);
}

const unsigned char keyboard_descriptor[] = "\x05\x01\x09\x06\xa1\x01\x05\x07\x19\xe0\x29\xe7\x15\x00\x25\x01\x75\x01\x95\x08\x81\x02\x95\x01\x75\x08\x81\x03\x95\x05\x75\x01\x05\x08\x19\x01\x29\x05\x91\x02\x95\x01\x75\x03\x91\x03\x95\x06\x75\x08\x15\x00\x25\x65\x05\x07\x19\x00\x29\x65\x81\x00\xc0";

const uint8_t mouse_descriptor[] = {
  0x05, 0x01, // usage page generic desktop controls
  0x09, 0x02, // usage mouse
  0xa1, // collection begin
    0x01, // collection type application
    0x09, 0x01, // usage pointer
    0xa1, // collection begin
      0x00, // collection type physical
      0x05, 0x09, // usage page button
      0x19, 0x01, // usage minimum 1
      0x29, 0x20, // usage max 0x20
      0x15, 0x00, // logical min 0
      0x25, 0x01, // logical max 1
      // 8 buttons of 1 bit each
      0x95, 0x08, // report count 32
      0x75, 0x01, // report size 1
      0x81, 0x02, // input data var abs
      // 2 axis of 16bits each
      0x75, 0x10, // report size 16
      0x95, 0x01, // report count 1
      0x05, 0x01, // generic desktop controls

      0x09, 0x30, // usage x
      0x15, 0x00, // logicalmin 0
      0x26, 0x80, 0x07, // logicalmax 1920
      0x81, 0x02, // input data var abs

      0x95, 0x01, // report count 1
      0x09, 0x31, // usage y
      0x26, 0x38, 0x04, // logicalmax 1080
      0x81, 0x02, // input data var abs

      // 1 axis of 8 bits
      0x75, 0x08, // report size 8
      0x95, 0x01, // report count 1
      0x05, 0x01, // generic desktop controls
      0x09, 0x38, // usage wheel
      0x15, 0x81, // logicalmin -127
      0x25, 0x7f, // logicalmax 127
      0x81, 0x06, // input data var rel
    0xc0, // collection end
  0xc0, // collection end
};

Gadget::Gadget(const char *hostname) {
  writefile("/sys/kernel/config/usb_gadget/g1/UDC", "");

  system("modprobe usb_f_hid");
  system("find /sys/kernel/config/usb_gadget/g1 -delete");
  chdir("/sys/kernel/config/usb_gadget");
  mkdir("g1", 0777);
  chdir("g1");
  mkdir("functions/hid.keyboard", 0777);
  mkdir("functions/hid.mouse", 0777);

  writefile("functions/hid.keyboard/protocol", "1");
  writefile("functions/hid.keyboard/subclass", "1");
  writefile("functions/hid.keyboard/report_length", "8");
  write_binary_file("functions/hid.keyboard/report_desc", keyboard_descriptor, sizeof(keyboard_descriptor));

  writefile("functions/hid.mouse/protocol", "2");
  writefile("functions/hid.mouse/subclass", "0");
  writefile("functions/hid.mouse/report_length", "6");
  write_binary_file("functions/hid.mouse/report_desc", mouse_descriptor, sizeof(mouse_descriptor));

  mkdir("configs/c.1", 0777);
  mkdir("strings/0x409", 0777);

  writefile("strings/0x409/manufacturer", "cleverca22");
  writefile("strings/0x409/product", "barrier gadget");
  writefile("strings/0x409/serialnumber", hostname);

  int fd = open("configs/c.1", O_RDONLY);
  symlinkat("functions/hid.keyboard", fd, "hid.keyboard");
  symlinkat("functions/hid.mouse", fd, "hid.mouse");
  close(fd);

  system("ls /sys/class/udc/ > UDC");
}

int main(int argc, char **argv) {
  Gadget g("amd-nixos");
  BarrierClient bc = BarrierClient("10.0.0.15", 24800, "thinkpad");
  bc.loop();
  return 0;
}
