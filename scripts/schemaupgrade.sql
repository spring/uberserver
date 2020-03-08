-- #40 renames.new is redundant
alter table renames drop new;

-- #61 rename lobby_id in logins to agent
alter table logins change column lobby_id agent;

-- #333 cleanup channel
alter table channel drop topic_time, autokick, antishock;

-- #359 uniqueness for dbuser.email
update users set email = None where email == '';
alter table users add unique(email);

-- #360 split last_id
update users set last_id = None where last_id == '';
update users
set last_sys_id = newdata.sysid
set last_mac_id = newdata.macid
from
(
select id,
SUBSTRING_INDEX(last_id,' ',1) sysid,
SUBSTRING_INDEX(last_id,' ',-1) macid
from users
) newdata
where
id = newdata.id;

-- 368 remove randsalt from dbuser
alter table users drop randsalt;
