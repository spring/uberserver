alter table channels change column owner_userid owner_user_id int;
alter table channels change column topic_userid topic_user_id int;
alter table channels drop owner;
alter table channels drop topic_owner;


