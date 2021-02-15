use crate::Role;

#[derive(Debug)]
pub struct LiteSessionData<T> {
    username: String,
    role: Role,
    tag: Option<String>,
    acl: Vec<T>,
}

impl<T> Default for LiteSessionData<T> {
    fn default() -> Self {
        Self {
            username: String::default(),
            role: Role::default(),
            tag: Option::default(),
            acl: Vec::default(),
        }
    }
}

impl<T> LiteSessionData<T>
where
    T: core::fmt::Display + core::fmt::Debug + core::cmp::Ord,
{
    pub fn username(&mut self, value: &str) -> &mut Self {
        self.username = value.into();

        self
    }

    pub fn role(&mut self, role: Role) -> &mut Self {
        self.role = role;

        self
    }

    pub fn tag(&mut self, tag: &str) -> &mut Self {
        self.tag = Some(tag.into());

        self
    }

    pub fn add_acl(&mut self, resourse: T) -> &mut Self {
        self.acl.push(resourse.into());

        self
    }

    pub fn remove_acl(&mut self, resource: T) -> Option<&mut Self> {
        match self.acl.binary_search(&resource.into()) {
            Ok(index) => {
                self.acl.remove(index);
                Some(self)
            }
            Err(_) => None,
        }
    }

    pub fn build(&self) -> String {
        let mut acl_token = String::default();
        let ls_separator = '⥂';
        let acl_separator = '⇅';
        let mut acl_list = String::default();

        acl_token.push_str(&self.username);
        acl_token.push(ls_separator);
        acl_token.push_str(&Role::to_string(&self.role));
        acl_token.push(ls_separator);

        match &self.tag {
            None => (),
            Some(tag) => acl_token.push_str(&tag),
        }

        let initial = &self.acl[0];
        acl_list.push_str(&format!("{:?}", initial));
        self.acl.iter().skip(1).for_each(|item| {
            acl_list.push(acl_separator);
            acl_list.push_str(&format!("{:?}", item))
        });
        acl_token.push(ls_separator);
        acl_token.push_str(&acl_list);

        acl_token
    }
}
